//! Concurrent in-memory session event store.

use lovebird_common::SessionState;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// Kind of recorded session activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Request,
    FailedAuth,
    MfaPrompt,
}

/// A single activity sample. Timestamps and geo are caller-injected.
#[derive(Debug, Clone)]
pub struct SessionEvent {
    pub principal_id: String,
    /// Unix epoch seconds (injected; not read from the wall clock here).
    pub at_unix_secs: i64,
    pub kind: EventKind,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Default)]
struct PrincipalHistory {
    events: VecDeque<SessionEvent>,
    state: SessionState,
}

/// Thread-safe store keyed by principal id.
#[derive(Debug, Clone, Default)]
pub struct SessionStore {
    inner: Arc<Mutex<HashMap<String, PrincipalHistory>>>,
    /// Soft cap per principal to bound memory.
    max_events_per_principal: usize,
}

impl SessionStore {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())), max_events_per_principal: 2_048 }
    }

    pub fn with_capacity_per_principal(max_events_per_principal: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_events_per_principal: max_events_per_principal.max(16),
        }
    }

    /// Append an event. Does not recompute scores — call [`crate::BehaviorAnalyzer`].
    pub fn record(&self, event: SessionEvent) -> Result<(), StoreError> {
        let mut map = self.inner.lock().map_err(|_| StoreError::LockPoisoned)?;
        let hist = map.entry(event.principal_id.clone()).or_insert_with(|| PrincipalHistory {
            events: VecDeque::new(),
            state: SessionState {
                principal_id: event.principal_id.clone(),
                ..SessionState::default()
            },
        });
        hist.events.push_back(event);
        while hist.events.len() > self.max_events_per_principal {
            hist.events.pop_front();
        }
        Ok(())
    }

    pub fn get(&self, principal_id: &str) -> Result<Option<SessionState>, StoreError> {
        let map = self.inner.lock().map_err(|_| StoreError::LockPoisoned)?;
        Ok(map.get(principal_id).map(|h| h.state.clone()))
    }

    pub fn clear(&self, principal_id: &str) -> Result<(), StoreError> {
        let mut map = self.inner.lock().map_err(|_| StoreError::LockPoisoned)?;
        map.remove(principal_id);
        Ok(())
    }

    pub(crate) fn with_history_mut<R>(
        &self,
        principal_id: &str,
        f: impl FnOnce(&mut VecDeque<SessionEvent>, &mut SessionState) -> R,
    ) -> Result<Option<R>, StoreError> {
        let mut map = self.inner.lock().map_err(|_| StoreError::LockPoisoned)?;
        match map.get_mut(principal_id) {
            Some(hist) => Ok(Some(f(&mut hist.events, &mut hist.state))),
            None => Ok(None),
        }
    }

    pub(crate) fn ensure_principal(&self, principal_id: &str) -> Result<(), StoreError> {
        let mut map = self.inner.lock().map_err(|_| StoreError::LockPoisoned)?;
        map.entry(principal_id.to_string()).or_insert_with(|| PrincipalHistory {
            events: VecDeque::new(),
            state: SessionState {
                principal_id: principal_id.to_string(),
                ..SessionState::default()
            },
        });
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    LockPoisoned,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::LockPoisoned => write!(f, "session store lock poisoned"),
        }
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_clears() {
        let store = SessionStore::new();
        store
            .record(SessionEvent {
                principal_id: "u1".into(),
                at_unix_secs: 1_000,
                kind: EventKind::Request,
                latitude: None,
                longitude: None,
            })
            .expect("record");
        assert!(store.get("u1").expect("get").is_some());
        store.clear("u1").expect("clear");
        assert!(store.get("u1").expect("get").is_none());
    }
}
