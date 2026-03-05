/// Grant response validation — RFC 9635 Section 3
use crate::types::{AccessTokenResponseField, ComplianceError, GrantResponse};

/// Validate a grant response for RFC 9635 compliance.
pub fn validate_grant_response(resp: &GrantResponse) -> Result<(), Vec<ComplianceError>> {
    let mut errors = Vec::new();

    // A grant response must contain at least one of: continue, access_token, interact, subject, error
    // RFC 9635 Section 3
    if resp.continue_.is_none()
        && resp.access_token.is_none()
        && resp.interact.is_none()
        && resp.subject.is_none()
        && resp.instance_id.is_none()
        && resp.error.is_none()
    {
        errors.push(ComplianceError::Validation(
            "Grant response must contain at least one field (Section 3)".to_string(),
        ));
    }

    // Validate continue if present
    if let Some(cont) = &resp.continue_ {
        if cont.access_token.value.is_empty() {
            errors.push(ComplianceError::Validation(
                "continue.access_token.value must not be empty (Section 3.1)".to_string(),
            ));
        }
        if cont.uri.is_empty() {
            errors.push(ComplianceError::Validation(
                "continue.uri must not be empty (Section 3.1)".to_string(),
            ));
        }
    }

    // Validate access_token if present
    if let Some(token_field) = &resp.access_token {
        validate_access_token_response(token_field, &mut errors);
    }

    // RFC 9635 Section 3.6: error MUST NOT be combined with access_token, interact, subject, instance_id
    if resp.error.is_some()
        && (resp.access_token.is_some()
            || resp.interact.is_some()
            || resp.subject.is_some()
            || resp.instance_id.is_some())
    {
        errors.push(ComplianceError::Validation(
            "When error is present, only continue may also be present (Section 3.6)".to_string(),
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_single_token(
    token: &crate::types::AccessToken,
    prefix: &str,
    errors: &mut Vec<ComplianceError>,
) {
    if token.value.is_empty() {
        errors.push(ComplianceError::Validation(format!(
            "{prefix}.value must not be empty (Section 3.2)"
        )));
    }
    if token.access.is_empty() {
        errors.push(ComplianceError::Validation(format!(
            "{prefix}.access must not be empty (Section 3.2.1)"
        )));
    }
    // Section 3.2.1: bearer flag and key field are mutually exclusive.
    if let Some(flags) = &token.flags {
        if flags.contains(&"bearer".to_string()) && token.key.is_some() {
            errors.push(ComplianceError::Validation(format!(
                "{prefix}: bearer flag and key must not both be present (Section 3.2.1)"
            )));
        }
        // Section 3.2.1: flag values MUST NOT be duplicated.
        let mut seen = std::collections::HashSet::new();
        for flag in flags {
            if !seen.insert(flag) {
                errors.push(ComplianceError::Validation(format!(
                    "{prefix}: duplicate flag \"{flag}\" (Section 3.2.1)"
                )));
            }
        }
    }
    // Section 3.2.1: management token value MUST differ from managed token value.
    if let Some(manage) = &token.manage {
        if manage.access_token.value == token.value {
            errors.push(ComplianceError::Validation(format!(
                "{prefix}: manage.access_token.value must differ from token value (Section 3.2.1)"
            )));
        }
    }
}

fn validate_access_token_response(
    field: &AccessTokenResponseField,
    errors: &mut Vec<ComplianceError>,
) {
    match field {
        AccessTokenResponseField::Single(token) => {
            validate_single_token(token, "access_token", errors);
        }
        AccessTokenResponseField::Multiple(tokens) => {
            if tokens.is_empty() {
                errors.push(ComplianceError::Validation(
                    "access_token array must not be empty (Section 3.2)".to_string(),
                ));
            }
            for (i, token) in tokens.iter().enumerate() {
                validate_single_token(token, &format!("access_token[{i}]"), errors);
                if token.label.is_none() {
                    errors.push(ComplianceError::Validation(format!(
                        "access_token[{i}].label is required for multi-token responses (Section 3.2)"
                    )));
                }
            }
            if let Some(e) = super::helpers::check_labels_unique(
                tokens.iter().map(|t| t.label.as_deref()),
                "Section 3.2",
            ) {
                errors.push(e);
            }
        }
    }
}
