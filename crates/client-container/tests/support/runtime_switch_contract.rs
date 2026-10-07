//! The supersede guards shared by both HTTP fixtures. Keep aligned with
//! app/client_runtime_switch.py; test_completed_apply_panel_contract.py checks
//! the completed-apply boundary against that real service in isolated SQLite.
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};
use std::collections::HashMap;

type ApiError = (StatusCode, Json<Value>);

#[derive(Default)]
pub struct RuntimeSwitchContract {
    transitions: HashMap<String, (Option<u64>, bool)>,
    reconciles: HashMap<String, Value>,
    supersedes: HashMap<String, Value>,
}

fn conflict(code: &str) -> ApiError {
    (
        StatusCode::CONFLICT,
        Json(json!({"request_id":"r", "code":code, "message":"transition conflict"})),
    )
}

impl RuntimeSwitchContract {
    pub fn reconcile(&mut self, body: &Value) -> Result<(), ApiError> {
        let id = body["operation_id"].as_str().unwrap();
        if self.supersedes.contains_key(id)
            || self.reconciles.get(id).is_some_and(|saved| saved != body)
        {
            return Err(conflict("runtime_switch_operation_conflict"));
        }
        self.reconciles.insert(id.into(), body.clone());
        self.transitions
            .entry(id.into())
            .or_insert((body["expected_session_generation"].as_u64(), true));
        Ok(())
    }

    pub fn resume(&mut self, body: &Value) {
        self.transitions.insert(
            body["reconcile_operation_id"].as_str().unwrap().into(),
            (body["expected_session_generation"].as_u64(), false),
        );
    }

    pub fn supersede(&mut self, body: &Value) -> Result<(), ApiError> {
        let id = body["operation_id"].as_str().unwrap();
        if let Some(saved) = self.supersedes.get(id) {
            return if saved == body {
                Ok(())
            } else {
                Err(conflict("runtime_switch_operation_conflict"))
            };
        }
        if self.reconciles.contains_key(id) {
            return Err(conflict("runtime_switch_operation_conflict"));
        }
        let predecessor = body["superseded_reconcile_operation_id"].as_str().unwrap();
        let Some((generation, blocked)) = self.transitions.get_mut(predecessor) else {
            return Err(conflict("runtime_switch_supersede_conflict"));
        };
        if !*blocked {
            return Err(conflict("runtime_switch_supersede_conflict"));
        }
        if *generation != body["expected_session_generation"].as_u64() {
            return Err(conflict("runtime_switch_generation_conflict"));
        }
        *blocked = false;
        let generation = *generation;
        self.transitions.insert(id.into(), (generation, true));
        self.supersedes.insert(id.into(), body.clone());
        Ok(())
    }
}
