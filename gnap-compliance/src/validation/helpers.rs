use crate::types::ComplianceError;

/// Check that all labels in the given iterator are unique.
pub(crate) fn check_labels_unique<'a>(
    labels: impl Iterator<Item = Option<&'a str>>,
    section: &str,
) -> Option<ComplianceError> {
    let labels: Vec<&str> = labels.flatten().collect();
    let unique: std::collections::HashSet<&str> = labels.iter().copied().collect();
    if labels.len() != unique.len() {
        Some(ComplianceError::Validation(format!(
            "access_token labels must be unique ({section})"
        )))
    } else {
        None
    }
}
