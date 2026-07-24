# Promoting Lovebird on GitHub

GitHub does not auto-tweet for you. Promotion is mostly **discoverability signals** you control + **content that people share**.

## Automated / one-time setup (do these)

1. **Repo description + topics** (search ranking)
   ```bash
   gh repo edit --description "Offline-first security decision engine — embeddable policy core with explainable, signed decisions"
   gh repo edit --add-topic policy-engine --add-topic authorization --add-topic rust \
     --add-topic security --add-topic opa --add-topic offline --add-topic zero-trust \
     --add-topic audit --add-topic access-control
   ```
2. **Root README** with badges, honest status, 30-second quickstart (this repo’s main door).
3. **Social preview** — GitHub picks the first image in the README (`docs/assets/lovebird-banner.svg`).
4. **CI badge** — green builds are social proof; keep Actions public.
5. **Releases** — tag `v0.1.0` when the engine+CLI are the story; Release notes get into GitHub’s Explore/Release feeds.
6. **Pin the repo** on your profile (`gh api user` → profile pin in UI).

## Semi-automatic loops

| Loop | How |
|---|---|
| Every green CI | Badge stays green → trust |
| Every release | `gh release create` with changelog |
| Every useful example | Link from README “Quick start” |
| Discussions / Issues | Good first issues labeled for contributors |

## What actually grows stars

- A **clear one-liner** in the description
- A README that answers “why not OPA?” in one screen
- A working `cargo run` demo in &lt; 60 seconds
- Posts outside GitHub (blog, HN “Show HN”, Reddit r/rust, LinkedIn) linking here — GitHub alone rarely virals unknown repos

## Don’t

- Fake activity / star farms
- Overclaim (“AI SIEM”) — security engineers bounce
- Bury the install under 2k words of architecture
