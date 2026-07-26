use nelomai_client_updater::{UpdateOffer, UpdateOfferError};
use nelomai_contracts::UpdateState;

fn update_state(version: Option<&str>, available: bool) -> UpdateState {
    UpdateState {
        current_version: version.map(ToOwned::to_owned),
        minimum_version: None,
        update_available: available,
        required: true,
        release_notes: Some("Критическое обновление.".to_string()),
    }
}

#[test]
fn bootstrap_update_becomes_an_offer_only_when_available() {
    assert_eq!(
        UpdateOffer::from_state(&update_state(Some("0.2.0"), false)).unwrap(),
        None
    );
    assert_eq!(
        UpdateOffer::from_state(&update_state(Some("0.2.0"), true)).unwrap(),
        Some(UpdateOffer {
            version: "0.2.0".to_string(),
            notes: Some("Критическое обновление.".to_string()),
            required: true,
        })
    );
}

#[test]
fn available_update_requires_a_valid_semantic_version() {
    assert_eq!(
        UpdateOffer::from_state(&update_state(None, true)).unwrap_err(),
        UpdateOfferError::MissingVersion
    );
    assert_eq!(
        UpdateOffer::from_state(&update_state(Some("tomorrow"), true)).unwrap_err(),
        UpdateOfferError::InvalidVersion
    );
}
