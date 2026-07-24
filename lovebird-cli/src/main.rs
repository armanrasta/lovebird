//! Lovebird offline operator CLI.
//!
//! No network access required for policy / audit commands.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use lovebird_engine::{
    AuditEntry, DecisionSigner, Effect, Evaluator, LintSeverity, Policy, Request, TrafficRecord,
    diff_policies, dry_run, lint_policies, validate_policies,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "lovebird", version, about = "Lovebird offline policy & audit tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Policy {
        #[command(subcommand)]
        command: PolicyCmd,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCmd,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Validate one or more policy JSON files (collects all errors)
    Validate { files: Vec<PathBuf> },
    /// Semantic warnings (does not block unless --strict)
    Lint {
        files: Vec<PathBuf>,
        #[arg(long)]
        strict: bool,
    },
    /// Run request scenarios against a policy set
    Test {
        policies: PathBuf,
        scenarios: PathBuf,
        #[arg(long)]
        explain: bool,
    },
    /// Replay traffic JSONL against candidate policies
    DryRun {
        /// Candidate policy file
        policies: PathBuf,
        /// JSONL of { request, prior_effect }
        #[arg(long = "against")]
        against: PathBuf,
        /// Exit non-zero if newly_denied > this threshold (default: no threshold)
        #[arg(long)]
        max_newly_denied: Option<usize>,
    },
    /// Compare two policy files structurally
    Diff {
        old: PathBuf,
        new: PathBuf,
        /// Optional traffic JSONL to estimate impact of `new`
        #[arg(long)]
        estimate_impact: Option<PathBuf>,
    },
    /// Compare production vs shadow policy sets over traffic / scenarios
    ShadowReport {
        production: PathBuf,
        shadow: PathBuf,
        /// JSONL TrafficRecord or scenarios with request field
        #[arg(long = "against")]
        against: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    Verify { file: PathBuf },
}

#[derive(serde::Deserialize)]
struct Scenario {
    request: Request,
    expected_effect: Effect,
    #[serde(default)]
    name: Option<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Policy { command } => match command {
            PolicyCmd::Validate { files } => cmd_validate(&files),
            PolicyCmd::Lint { files, strict } => cmd_lint(&files, strict),
            PolicyCmd::Test { policies, scenarios, explain } => {
                cmd_test(&policies, &scenarios, explain)
            }
            PolicyCmd::DryRun { policies, against, max_newly_denied } => {
                cmd_dry_run(&policies, &against, max_newly_denied)
            }
            PolicyCmd::Diff { old, new, estimate_impact } => {
                cmd_diff(&old, &new, estimate_impact.as_deref())
            }
            PolicyCmd::ShadowReport { production, shadow, against } => {
                cmd_shadow(&production, &shadow, &against)
            }
        },
        Commands::Audit { command } => match command {
            AuditCmd::Verify { file } => cmd_audit_verify(&file),
        },
    }
}

fn load_policies(path: &Path) -> Result<Vec<Policy>> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    if value.is_array() {
        serde_json::from_value(value).context("deserializing policy array")
    } else {
        let p: Policy = serde_json::from_value(value).context("deserializing policy")?;
        Ok(vec![p])
    }
}

fn load_traffic(path: &Path) -> Result<Vec<TrafficRecord>> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    // JSON array or JSONL
    if let Ok(records) = serde_json::from_str::<Vec<TrafficRecord>>(raw.trim()) {
        return Ok(records);
    }
    let mut records = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: TrafficRecord = serde_json::from_str(line)
            .with_context(|| format!("line {}: parse TrafficRecord", i + 1))?;
        records.push(rec);
    }
    if records.is_empty() {
        bail!("no traffic records in {}", path.display());
    }
    Ok(records)
}

fn cmd_validate(files: &[PathBuf]) -> Result<ExitCode> {
    if files.is_empty() {
        bail!("provide at least one policy file");
    }
    let mut all_policies = Vec::new();
    for f in files {
        all_policies.extend(load_policies(f)?);
    }

    match validate_policies(&all_policies) {
        Ok(()) => {
            println!("OK — {} polic(y/ies) valid", all_policies.len());
            Ok(ExitCode::SUCCESS)
        }
        Err(errors) => {
            eprintln!("FAIL — {} error(s):", errors.len());
            for e in &errors {
                eprintln!("  • {e}");
            }
            Ok(ExitCode::FAILURE)
        }
    }
}

fn cmd_lint(files: &[PathBuf], strict: bool) -> Result<ExitCode> {
    if files.is_empty() {
        bail!("provide at least one policy file");
    }
    let mut all = Vec::new();
    for f in files {
        all.extend(load_policies(f)?);
    }
    // Still validate first so lint isn't confused by illegal policies
    if let Err(errors) = validate_policies(&all) {
        eprintln!("FAIL — fix validation errors before lint ({}):", errors.len());
        for e in &errors {
            eprintln!("  • {e}");
        }
        return Ok(ExitCode::FAILURE);
    }

    let findings = lint_policies(&all);
    if findings.is_empty() {
        println!("OK — no lint findings");
        return Ok(ExitCode::SUCCESS);
    }
    for f in &findings {
        eprintln!("{f}");
    }
    let warnings = findings.iter().filter(|f| f.severity == LintSeverity::Warning).count();
    println!("DONE — {} finding(s) ({} warning(s))", findings.len(), warnings);
    if strict && warnings > 0 { Ok(ExitCode::FAILURE) } else { Ok(ExitCode::SUCCESS) }
}

fn cmd_test(policies_path: &Path, scenarios_path: &Path, explain: bool) -> Result<ExitCode> {
    let policies = load_policies(policies_path)?;
    validate_policies(&policies).map_err(|errs| {
        let msg = errs.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join("; ");
        anyhow::anyhow!("policies failed validation: {msg}")
    })?;

    let raw = fs::read_to_string(scenarios_path)
        .with_context(|| format!("reading {}", scenarios_path.display()))?;
    let scenarios: Vec<Scenario> =
        serde_json::from_str(&raw).context("parsing scenarios JSON array")?;

    let evaluator = Evaluator::new().with_explain(explain);
    let mut failed = 0usize;

    for (i, scenario) in scenarios.iter().enumerate() {
        let label = scenario.name.clone().unwrap_or_else(|| format!("scenario[{i}]"));
        let decision = evaluator.evaluate(&scenario.request, &policies);
        if decision.effect == scenario.expected_effect {
            println!("PASS  {label} → {:?}", decision.effect);
            if explain && let Some(ref expl) = decision.explanation {
                for line in &expl.why {
                    println!("        {line}");
                }
            }
        } else {
            failed += 1;
            println!(
                "FAIL  {label} → got {:?}, expected {:?}",
                decision.effect, scenario.expected_effect
            );
            if let Some(ref expl) = decision.explanation {
                for line in &expl.why {
                    println!("        {line}");
                }
            }
        }
    }

    if failed == 0 {
        println!("OK — {}/{} scenarios passed", scenarios.len(), scenarios.len());
        Ok(ExitCode::SUCCESS)
    } else {
        println!("DONE — {}/{} scenarios failed", failed, scenarios.len());
        Ok(ExitCode::FAILURE)
    }
}

fn cmd_dry_run(
    policies_path: &Path,
    traffic_path: &Path,
    max_newly_denied: Option<usize>,
) -> Result<ExitCode> {
    let policies = load_policies(policies_path)?;
    validate_policies(&policies).map_err(|e| {
        anyhow::anyhow!(
            "invalid policies: {}",
            e.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join("; ")
        )
    })?;
    let traffic = load_traffic(traffic_path)?;
    let report = dry_run(&Evaluator::new(), &policies, &traffic);

    println!("If these policies were active:");
    println!("  total:          {}", report.total);
    println!("  unchanged:      {}", report.unchanged);
    println!("  newly denied:   {}", report.newly_denied);
    println!("  newly allowed:  {}", report.newly_allowed);
    if !report.affected_principals.is_empty() {
        println!("  affected:       {}", report.affected_principals.join(", "));
    }

    if let Some(max) = max_newly_denied
        && report.newly_denied > max
    {
        eprintln!("FAIL — newly_denied {} exceeds threshold {}", report.newly_denied, max);
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_diff(old_path: &Path, new_path: &Path, impact: Option<&Path>) -> Result<ExitCode> {
    let old = load_policies(old_path)?;
    let new = load_policies(new_path)?;
    let entries = diff_policies(&old, &new);
    if entries.is_empty() {
        println!("OK — no differences");
    } else {
        for e in &entries {
            if e.detail.is_empty() {
                println!("{}: {}", e.change, e.policy_id);
            } else {
                println!("{}: {} — {}", e.change, e.policy_id, e.detail);
            }
        }
        println!("DONE — {} change(s)", entries.len());
    }

    if let Some(traffic_path) = impact {
        let traffic = load_traffic(traffic_path)?;
        // Baseline = old policies' decisions as prior_effect
        let ev = Evaluator::new();
        let mut rewritten = Vec::new();
        for rec in traffic {
            let prior = ev.evaluate(&rec.request, &old).effect;
            rewritten.push(TrafficRecord {
                request: rec.request,
                prior_effect: prior,
                principal_hint: rec.principal_hint,
            });
        }
        let report = dry_run(&ev, &new, &rewritten);
        println!();
        println!("Estimated impact of `new` vs `old` on traffic:");
        println!("  newly denied:  {}", report.newly_denied);
        println!("  newly allowed: {}", report.newly_allowed);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_shadow(production: &Path, shadow: &Path, against: &Path) -> Result<ExitCode> {
    let prod = load_policies(production)?;
    let sh = load_policies(shadow)?;
    let traffic = load_traffic(against)?;
    let ev = Evaluator::new();
    let mut agree = 0usize;
    let mut disagree = 0usize;

    for rec in &traffic {
        let report = ev.evaluate_shadow(&rec.request, &prod, &sh);
        if report.agree {
            agree += 1;
        } else {
            disagree += 1;
            println!(
                "DIFF principal={} action={} actual={:?} shadow={:?}",
                rec.request.principal.id,
                rec.request.action,
                report.actual.effect,
                report.shadow.effect
            );
        }
    }

    let total = agree + disagree;
    let pct10 = agree.saturating_mul(1000).checked_div(total).unwrap_or(1000);
    println!(
        "Shadow agreement: {}.{:01}% ({agree}/{total} agree, {disagree} differ)",
        pct10 / 10,
        pct10 % 10
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_audit_verify(path: &Path) -> Result<ExitCode> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut ok = 0usize;
    let mut bad = 0usize;

    if let Ok(entry) = serde_json::from_str::<AuditEntry>(raw.trim()) {
        match DecisionSigner::verify_entry(&entry) {
            Ok(()) => ok += 1,
            Err(e) => {
                bad += 1;
                eprintln!("FAIL — {e}");
            }
        }
    } else {
        for (line_no, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(line)
                .with_context(|| format!("line {}: parse AuditEntry", line_no + 1))?;
            match DecisionSigner::verify_entry(&entry) {
                Ok(()) => ok += 1,
                Err(e) => {
                    bad += 1;
                    eprintln!("line {}: FAIL — {e}", line_no + 1);
                }
            }
        }
    }

    if bad == 0 && ok > 0 {
        println!("OK — {ok} entr(y/ies) verified");
        Ok(ExitCode::SUCCESS)
    } else if ok == 0 && bad == 0 {
        bail!("no audit entries found in {}", path.display());
    } else {
        println!("DONE — {ok} ok, {bad} failed");
        Ok(ExitCode::FAILURE)
    }
}
