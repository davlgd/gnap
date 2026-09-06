//! A two-token grant under one consent: `documents` and `reports`, each with
//! its own rights, its own resource server and its own management (RFC 9635
//! §§2.1.2, 3.2.2). The single-token flow keeps its existing behaviour.
use super::*;
use gnap_as::{MemoryResourceSetStore, TokenApproval};
use gnap_types::token::Cardinality;

pub(super) const REPORTS_READ: &str = "synthetic-reports:read";
pub(super) const REPORTS_PATH: &str = "/resource/reports";
pub(super) const DOCUMENTS: &str = "documents";
pub(super) const REPORTS: &str = "reports";

/// Which flow a browser session started. Kept explicitly for the session's
/// lifetime, never inferred from how many tokens happen to be held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    Single,
    Multiple,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Multiple => "multiple",
        }
    }
}

pub(super) fn is_start(action: &str) -> bool {
    matches!(action, "start" | "start-multiple")
}

/// What the resource owner chose for a pending request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Choice {
    Denied,
    /// Every requested token, whatever its label.
    All,
    /// Only the tokens carrying these labels; a lot may be approved in part
    /// (§3.2.2: "The AS MAY refuse to issue one or more of the requested
    /// access tokens for any reason").
    Only(Vec<String>),
}

impl Choice {
    pub fn from_action(action: &str) -> Option<Self> {
        match action {
            "approve" => Some(Self::All),
            "deny" => Some(Self::Denied),
            "approve-reports" => Some(Self::Only(vec![REPORTS.to_owned()])),
            _ => None,
        }
    }
    fn allows(&self, label: Option<&str>) -> bool {
        match self {
            Self::Denied => false,
            Self::All => true,
            Self::Only(labels) => label.is_some_and(|label| labels.iter().any(|l| l == label)),
        }
    }
}

/// One requested token, resolved to the leaf rights the AS understands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Slot {
    pub label: Option<String>,
    pub rights: Vec<AccessItem>,
}

/// The request as this deployment understands it, or `None` when it is not
/// something the AS issues: a single token resolved exactly as before, or a
/// lot of at most two tokens labelled `documents` (references or leaves of the
/// document RS) and `reports` (exactly the reports leaf). In a lot, no other
/// label, right, flag or extension is accepted; the single flow keeps the
/// checks it always had. RS1 acting as a client is refused as before.
pub(super) fn requested_slots(
    request: &GrantRequest,
    resources: &MemoryResourceSetStore,
) -> Option<Vec<Slot>> {
    if request.client.as_reference() == Some(introspection::RS_ID) {
        return None;
    }
    let tokens = request.access_token.as_ref()?;
    if tokens.cardinality == Cardinality::Single {
        return requested_rights(request, resources).map(|rights| {
            vec![Slot {
                label: tokens.tokens[0].label.clone(),
                rights,
            }]
        });
    }
    if tokens.tokens.is_empty() || tokens.tokens.len() > 2 {
        return None;
    }
    let mut slots = Vec::with_capacity(tokens.tokens.len());
    for token in &tokens.tokens {
        if !token.flags.is_empty() || !token.extra.is_empty() {
            return None;
        }
        let rights = match token.label.as_deref()? {
            DOCUMENTS => resolve_rights(&token.access, resources)?,
            REPORTS if token.access == [AccessItem::Reference(REPORTS_READ.into())] => {
                token.access.clone()
            }
            _ => return None,
        };
        slots.push(Slot {
            label: token.label.clone(),
            rights,
        });
    }
    Some(slots)
}

/// The decision after the resource owner answered, for the slots they saw.
///
/// A single token is approved or denied as before. A lot is approved slot by
/// slot: the tokens the owner allowed are issued together as one grant, the
/// others are omitted from the response (§3.2.2). Allowing none of them is a
/// refusal.
pub(super) fn decision(mode: Cardinality, slots: &[Slot], choice: &Choice) -> Decision {
    let denied = Decision::Deny(gnap_registry::ErrorCode::UserDenied);
    match mode {
        Cardinality::Single => match slots {
            [slot] if choice.allows(slot.label.as_deref()) => Decision::Approve {
                access: slot.rights.clone(),
                subject: None,
            },
            _ => denied,
        },
        Cardinality::Multiple => {
            let tokens: Vec<_> = slots
                .iter()
                .filter(|slot| choice.allows(slot.label.as_deref()))
                .map(|slot| TokenApproval {
                    requested_label: slot.label.clone(),
                    access: slot.rights.clone(),
                })
                .collect();
            if tokens.is_empty() {
                denied
            } else {
                Decision::ApproveTokens {
                    tokens,
                    subject: None,
                }
            }
        }
    }
}

/// A modification that stays within what is already approved, compared label
/// by label: every requested slot must be covered by the live token carrying
/// the same label, never by the union of the grant's rights. Anything else
/// needs the resource owner again.
pub(super) fn modification(mode: Cardinality, slots: &[Slot], live: &GrantSnapshot) -> Decision {
    let time = now();
    let covered = |slot: &Slot| {
        live.aggregate
            .tokens
            .values()
            .filter(|token| token.is_valid_at(time) && token.token.label == slot.label)
            .any(|token| {
                let held = token.token.access.as_deref().unwrap_or_default();
                slot.rights.iter().all(|right| held.contains(right))
            })
    };
    if !slots.iter().all(covered) {
        return Decision::RequireInteraction;
    }
    decision(mode, slots, &Choice::All)
}

/// The two-token request the browser flow starts with: every document right
/// through the registered reference, and the reports leaf.
pub(super) fn lot(references: &resource_registration::References, expand: bool) -> Value {
    let documents = if expand {
        &references.both
    } else {
        &references.folder
    };
    let mut lot = vec![json!({"label": DOCUMENTS, "access": [documents]})];
    if expand {
        lot.push(json!({"label": REPORTS, "access": [REPORTS_READ]}));
    }
    Value::Array(lot)
}

/// What the browser flow asked for, slot by slot, as the consent view shows
/// it: the single flow's one unlabelled token, or the lot's labelled tokens.
pub(super) fn requested(mode: Mode, expand: bool) -> Vec<Slot> {
    match mode {
        Mode::Single => vec![Slot {
            label: None,
            rights: resource_registration::leaves(expand),
        }],
        Mode::Multiple => {
            let mut slots = vec![Slot {
                label: Some(DOCUMENTS.to_owned()),
                rights: resource_registration::leaves(expand),
            }];
            if expand {
                slots.push(Slot {
                    label: Some(REPORTS.to_owned()),
                    rights: vec![AccessItem::Reference(REPORTS_READ.into())],
                });
            }
            slots
        }
    }
}

/// The union of the requested leaves, for the existing summary line.
pub(super) fn requested_leaves(slots: &[Slot]) -> Vec<AccessItem> {
    let mut rights = Vec::new();
    for right in slots.iter().flat_map(|slot| slot.rights.iter()) {
        if !rights.contains(right) {
            rights.push(right.clone());
        }
    }
    rights
}

/// Requested slots as the browser may see them: labels and rights only.
pub(super) fn slots_view(slots: &[Slot]) -> Vec<Value> {
    slots
        .iter()
        .map(|slot| json!({"label": slot.label, "rights": slot.rights}))
        .collect()
}

/// A token the session retired, kept together with the label it was managed
/// under, so a later check names and targets the right resource server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Retired {
    pub value: TokenValue,
    pub label: Option<String>,
}

/// The label a management or resource action targets in this session's flow:
/// the single flow's only token carries no label; a lot names its tokens.
pub(super) fn label_for(mode: Mode, purpose: &'static str) -> Option<&'static str> {
    match mode {
        Mode::Single => None,
        Mode::Multiple => Some(purpose),
    }
}

/// The live token an action uses, chosen by label, never by position. A lot
/// approved in part has no `documents` token: actions on it are refused
/// locally rather than falling back to the other token.
pub(super) fn held<'t>(
    tokens: &'t [&'t gnap_types::token::AccessToken],
    mode: Mode,
    purpose: &str,
) -> Result<&'t gnap_types::token::AccessToken, String> {
    match mode {
        Mode::Single if purpose == DOCUMENTS => tokens.first().copied(),
        Mode::Single => None,
        Mode::Multiple => tokens
            .iter()
            .copied()
            .find(|token| token.label.as_deref() == Some(purpose)),
    }
    .ok_or_else(|| format!("No live {purpose} token in this grant"))
}

/// The tokens a session holds, as the browser may see them: labels and
/// rights, never values.
pub(super) fn view(tokens: Option<&Vec<&gnap_types::token::AccessToken>>) -> Vec<Value> {
    tokens
        .into_iter()
        .flatten()
        .map(|token| {
            json!({
                "label": token.label,
                "rights": token.access.as_deref().unwrap_or_default(),
            })
        })
        .collect()
}

/// The token the browser flow treats as "the" token before a change: the
/// `documents` token of a lot, the only token of the single flow. A lot with
/// no `documents` token has none, so nothing is retired in its name.
pub(super) fn primary(
    tokens: Option<Vec<&gnap_types::token::AccessToken>>,
    mode: Mode,
) -> Option<Retired> {
    let tokens = tokens?;
    held(&tokens, mode, DOCUMENTS).ok().map(|token| Retired {
        value: token.value.clone(),
        label: label_for(mode, DOCUMENTS).map(str::to_owned),
    })
}
