//! Deterministic behavioral heuristics (not ML).

use crate::store::{EventKind, SessionEvent, SessionStore, StoreError};
use lovebird_common::SessionState;

/// Thresholds for [`BehaviorAnalyzer`]. All comparisons are inclusive where noted.
#[derive(Debug, Clone)]
pub struct BehaviorConfig {
    /// Requests in the last 60s that start elevating anomaly score.
    pub velocity_warn: u32,
    /// Requests in the last 60s treated as a spike.
    pub velocity_spike: u32,
    /// Failed auths in the last 60s treated as credential stuffing.
    pub failed_auth_burst: u32,
    /// MFA prompts in the last `mfa_window_secs` treated as fatigue.
    pub mfa_fatigue_count: u32,
    pub mfa_window_secs: i64,
    /// Max plausible travel speed in km/h (commercial aviation ~900).
    pub max_travel_kmh: f64,
    /// Minimum seconds between geo samples before travel is evaluated.
    pub min_travel_interval_secs: i64,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            velocity_warn: 60,
            velocity_spike: 120,
            failed_auth_burst: 5,
            mfa_fatigue_count: 3,
            mfa_window_secs: 600,
            max_travel_kmh: 900.0,
            min_travel_interval_secs: 60,
        }
    }
}

/// Recomputes [`SessionState`] for a principal from stored events.
#[derive(Debug, Clone, Default)]
pub struct BehaviorAnalyzer {
    pub config: BehaviorConfig,
}

impl BehaviorAnalyzer {
    pub fn new(config: BehaviorConfig) -> Self {
        Self { config }
    }

    /// Recompute and persist state for `principal_id` as of `now_unix_secs`.
    pub fn recompute(
        &self,
        store: &SessionStore,
        principal_id: &str,
        now_unix_secs: i64,
    ) -> Result<SessionState, StoreError> {
        store.ensure_principal(principal_id)?;
        let out = store.with_history_mut(principal_id, |events, state| {
            *state = self.score(principal_id, events, now_unix_secs);
            state.clone()
        })?;
        match out {
            Some(s) => Ok(s),
            None => Ok(SessionState {
                principal_id: principal_id.to_string(),
                ..SessionState::default()
            }),
        }
    }

    /// Pure scoring over an event slice (useful in tests).
    pub fn score(
        &self,
        principal_id: &str,
        events: &std::collections::VecDeque<SessionEvent>,
        now_unix_secs: i64,
    ) -> SessionState {
        let minute_ago = now_unix_secs.saturating_sub(60);
        let mfa_ago = now_unix_secs.saturating_sub(self.config.mfa_window_secs);

        let mut request_count: u64 = 0;
        let mut requests_last_minute: u32 = 0;
        let mut failed_auth_count: u32 = 0;
        let mut failed_last_minute: u32 = 0;
        let mut mfa_in_window: u32 = 0;

        for ev in events {
            match ev.kind {
                EventKind::Request => {
                    request_count = request_count.saturating_add(1);
                    if ev.at_unix_secs >= minute_ago {
                        requests_last_minute = requests_last_minute.saturating_add(1);
                    }
                }
                EventKind::FailedAuth => {
                    failed_auth_count = failed_auth_count.saturating_add(1);
                    if ev.at_unix_secs >= minute_ago {
                        failed_last_minute = failed_last_minute.saturating_add(1);
                    }
                }
                EventKind::MfaPrompt => {
                    if ev.at_unix_secs >= mfa_ago {
                        mfa_in_window = mfa_in_window.saturating_add(1);
                    }
                }
            }
        }

        let impossible_travel_detected = self.detect_impossible_travel(events);
        let mut anomaly_score = 0.0_f64;

        if requests_last_minute >= self.config.velocity_spike {
            anomaly_score += 0.55;
        } else if requests_last_minute >= self.config.velocity_warn {
            anomaly_score += 0.35;
        }

        if failed_last_minute >= self.config.failed_auth_burst {
            anomaly_score += 0.30;
        }

        if mfa_in_window >= self.config.mfa_fatigue_count {
            anomaly_score += 0.25;
        }

        if impossible_travel_detected {
            anomaly_score += 0.50;
        }

        if anomaly_score > 1.0 {
            anomaly_score = 1.0;
        }

        SessionState {
            principal_id: principal_id.to_string(),
            anomaly_score,
            impossible_travel_detected,
            failed_auth_count,
            request_count,
            requests_last_minute,
        }
    }

    fn detect_impossible_travel(&self, events: &std::collections::VecDeque<SessionEvent>) -> bool {
        let mut last: Option<(i64, f64, f64)> = None;
        for ev in events {
            let (Some(lat), Some(lon)) = (ev.latitude, ev.longitude) else {
                continue;
            };
            if let Some((t0, lat0, lon0)) = last {
                let dt = ev.at_unix_secs.saturating_sub(t0);
                if dt >= self.config.min_travel_interval_secs {
                    let km = haversine_km(lat0, lon0, lat, lon);
                    let hours = f64::from(u32::try_from(dt).unwrap_or(u32::MAX)) / 3600.0;
                    if hours > 0.0 {
                        let speed = km / hours;
                        if speed > self.config.max_travel_kmh {
                            return true;
                        }
                    }
                }
            }
            last = Some((ev.at_unix_secs, lat, lon));
        }
        false
    }
}

/// Great-circle distance in kilometers.
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0;
    let to_rad = |d: f64| d * std::f64::consts::PI / 180.0;
    let (phi1, phi2) = (to_rad(lat1), to_rad(lat2));
    let d_phi = to_rad(lat2 - lat1);
    let d_lambda = to_rad(lon2 - lon1);
    let a = (d_phi / 2.0).sin().powi(2) + phi1.cos() * phi2.cos() * (d_lambda / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    R * c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SessionEvent;
    use std::collections::VecDeque;

    #[test]
    fn velocity_spike_raises_score() {
        let analyzer = BehaviorAnalyzer::default();
        let mut events = VecDeque::new();
        let now = 10_000_i64;
        for i in 0..130 {
            events.push_back(SessionEvent {
                principal_id: "u".into(),
                at_unix_secs: now - 30 + (i % 30),
                kind: EventKind::Request,
                latitude: None,
                longitude: None,
            });
        }
        let state = analyzer.score("u", &events, now);
        assert!(state.requests_last_minute >= 120);
        assert!(state.anomaly_score >= 0.55);
    }

    #[test]
    fn impossible_travel_nyc_to_tokyo() {
        let analyzer = BehaviorAnalyzer::default();
        let mut events = VecDeque::new();
        // NYC → Tokyo in 1 hour is impossible
        events.push_back(SessionEvent {
            principal_id: "u".into(),
            at_unix_secs: 1_000,
            kind: EventKind::Request,
            latitude: Some(40.7128),
            longitude: Some(-74.0060),
        });
        events.push_back(SessionEvent {
            principal_id: "u".into(),
            at_unix_secs: 1_000 + 3_600,
            kind: EventKind::Request,
            latitude: Some(35.6762),
            longitude: Some(139.6503),
        });
        let state = analyzer.score("u", &events, 1_000 + 3_600);
        assert!(state.impossible_travel_detected);
        assert!(state.anomaly_score >= 0.5);
    }

    #[test]
    fn haversine_nyc_london_ballpark() {
        let km = haversine_km(40.7128, -74.0060, 51.5074, -0.1278);
        assert!((5_500.0..6_000.0).contains(&km), "got {km}");
    }
}
