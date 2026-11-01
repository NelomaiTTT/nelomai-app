use nelomai_client_api::{ClientApiError, LoginRejection};
use reqwest::StatusCode;

#[test]
fn login_rejection_requires_definitive_status_and_allowlisted_code() {
    for (status, code, expected) in [
        (
            401,
            "invalid_credentials",
            Some(LoginRejection::InvalidCredentials),
        ),
        (
            403,
            "app_access_unavailable",
            Some(LoginRejection::AppAccessUnavailable),
        ),
        (
            409,
            "device_limit_reached",
            Some(LoginRejection::DeviceLimitReached),
        ),
        (
            429,
            "login_rate_limited",
            Some(LoginRejection::LoginRateLimited),
        ),
        (422, "invalid_request", Some(LoginRejection::InvalidRequest)),
        (409, "unknown_result", None),
        (500, "device_limit_reached", None),
        (409, "invalid_credentials", None),
        (401, "server-controlled-private-text", None),
    ] {
        let error = ClientApiError::Api {
            status: StatusCode::from_u16(status).unwrap(),
            request_id: "synthetic".into(),
            code: code.into(),
            message: "do-not-forward-panel-text".into(),
            retry_after_seconds: None,
        };
        let actual = LoginRejection::from_error(&error);
        assert_eq!(actual, expected, "HTTP {status} / {code}");
        if let Some(reason) = actual {
            assert_eq!(reason.code(), code);
            assert!(!serde_json::to_string(&reason)
                .unwrap()
                .contains("do-not-forward"));
        }
    }
}
