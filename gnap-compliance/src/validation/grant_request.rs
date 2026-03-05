/// Grant request validation — RFC 9635 Section 2
use crate::types::{
    AccessTokenRequestField, ClientInstance, ClientInstanceInfo, ComplianceError, GrantRequest,
};

/// Validate a grant request for RFC 9635 compliance.
pub fn validate_grant_request(req: &GrantRequest) -> Result<(), Vec<ComplianceError>> {
    let mut errors = Vec::new();

    if let Some(access_token) = &req.access_token {
        validate_access_token_request(access_token, &mut errors);
    }
    validate_client_instance(&req.client, &mut errors);

    if let Some(interact) = &req.interact {
        // RFC 9635 Section 2.5: start can be empty for push-only patterns
        // (finish with method "push" and no start modes).
        if interact.start.is_empty() && interact.finish.is_none() {
            errors.push(ComplianceError::Validation(
                "interact must have start modes or a finish method (Section 2.5)".to_string(),
            ));
        }
        if let Some(finish) = &interact.finish {
            if finish.nonce.is_empty() {
                errors.push(ComplianceError::Validation(
                    "interact.finish.nonce must not be empty (Section 2.5.2)".to_string(),
                ));
            }
            if finish.uri.is_empty() {
                errors.push(ComplianceError::Validation(
                    "interact.finish.uri must not be empty (Section 2.5.2)".to_string(),
                ));
            }
            let valid_methods = ["redirect", "push"];
            if !valid_methods.contains(&finish.method.as_str()) {
                errors.push(ComplianceError::Validation(format!(
                    "interact.finish.method must be \"redirect\" or \"push\", got \"{}\" (Section 2.5.2)",
                    finish.method
                )));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_access_token_request(
    field: &AccessTokenRequestField,
    errors: &mut Vec<ComplianceError>,
) {
    match field {
        AccessTokenRequestField::Single(req) => {
            if req.access.is_empty() {
                errors.push(ComplianceError::Validation(
                    "access_token.access must not be empty (Section 2.1)".to_string(),
                ));
            }
        }
        AccessTokenRequestField::Multiple(reqs) => {
            if reqs.is_empty() {
                errors.push(ComplianceError::Validation(
                    "access_token array must not be empty (Section 2.1)".to_string(),
                ));
            }
            for (i, req) in reqs.iter().enumerate() {
                if req.access.is_empty() {
                    errors.push(ComplianceError::Validation(format!(
                        "access_token[{i}].access must not be empty (Section 2.1)"
                    )));
                }
                if req.label.is_none() {
                    errors.push(ComplianceError::Validation(format!(
                        "access_token[{i}].label is required for multi-token requests (Section 2.1)"
                    )));
                }
            }
            if let Some(e) = super::helpers::check_labels_unique(
                reqs.iter().map(|r| r.label.as_deref()),
                "Section 2.1",
            ) {
                errors.push(e);
            }
        }
    }
}

fn validate_client_instance(client: &ClientInstance, errors: &mut Vec<ComplianceError>) {
    match client {
        ClientInstance::Reference(id) => {
            if id.is_empty() {
                errors.push(ComplianceError::Validation(
                    "client reference must not be empty (Section 2.3)".to_string(),
                ));
            }
        }
        ClientInstance::Inline(ClientInstanceInfo { key, .. }) => {
            use crate::types::KeyRef;
            match key {
                KeyRef::Inline(k) => {
                    if k.jwk.is_none() && k.cert.is_none() && k.cert_s256.is_none() {
                        errors.push(ComplianceError::Validation(
                            "client key must contain jwk, cert, or cert#S256 (Section 7.1)"
                                .to_string(),
                        ));
                    }
                }
                KeyRef::Reference(r) => {
                    if r.is_empty() {
                        errors.push(ComplianceError::Validation(
                            "client key reference must not be empty (Section 7.1)".to_string(),
                        ));
                    }
                }
            }
        }
    }
}
