//! Immutable resource-set storage for the opaque RS registration profile.
//!
//! This is separate from grants and their credentials. Registration does not
//! authorize a client. The grant policy resolves references to approved leaf
//! rights and retains those rights in tokens, avoiding mutable-reference drift.
//! No update, delete, TTL, recursive resolver or persistence protocol is supplied.

use gnap_types::access::AccessItem;
use std::{collections::HashMap, fmt, io, sync::Mutex};

/// Canonical RS identity assigned by the deployment's trusted key registry.
///
/// Neither a presented reference nor a JWK `kid` establishes this identity.
/// Key aliases and key rotation must retain the same owner when appropriate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RsId(pub String);

/// An immutable registration, scoped to the AS owning the resource store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSet {
    /// Public opaque reference; never an authorization credential.
    pub reference: String,
    /// Authenticated owner, not exposed in the registration response.
    pub owner: RsId,
    /// Canonical approved leaf rights; their internal strings remain exact.
    pub access: Vec<AccessItem>,
}

/// Explicit memory budgets, not additional GNAP wire requirements.
#[derive(Debug, Clone, Copy)]
pub struct ResourceSetLimits {
    /// Maximum live registrations in this AS store.
    pub max_sets: usize,
    /// Maximum registrations belonging to a single canonical RS identity.
    pub max_sets_per_owner: usize,
    /// Maximum rights supplied to one registration, before deduplication.
    pub max_access_items: usize,
    /// Maximum serialized access bytes plus owner and reference bytes per record.
    pub max_record_bytes: usize,
    /// Maximum UTF-8 bytes in the candidate reference and owner identity each.
    pub max_reference_bytes: usize,
    /// Maximum nesting of arbitrary JSON extension values before serialization.
    pub max_json_depth: usize,
    /// Maximum JSON extension nodes across all access objects in one request.
    pub max_json_nodes: usize,
}

impl Default for ResourceSetLimits {
    fn default() -> Self {
        Self {
            max_sets: 256,
            max_sets_per_owner: 32,
            max_access_items: 64,
            max_record_bytes: 64 * 1024,
            max_reference_bytes: 256,
            max_json_depth: 16,
            max_json_nodes: 4096,
        }
    }
}

/// Failure to confirm registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceSetError {
    /// Candidate reference already names a different immutable registration.
    Collision,
    /// Global or per-owner capacity reached; no existing record is evicted.
    Capacity,
    /// Submitted rights exceed input limits or cannot be represented safely.
    InvalidAccessInput,
    /// Invalid trusted owner/candidate metadata, configuration or adapter state.
    Invalid,
    /// Storage cannot reliably confirm the operation; a durable commit can be ambiguous.
    Unavailable,
}

impl fmt::Display for ResourceSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Collision => "resource reference collision",
            Self::Capacity => "resource registry capacity reached",
            Self::InvalidAccessInput => "invalid or over-budget resource access input",
            Self::Invalid => "invalid resource registration metadata or configuration",
            Self::Unavailable => "resource registry unavailable",
        })
    }
}
impl std::error::Error for ResourceSetError {}

/// AS-scoped immutable registry, independent of grant/token storage.
///
/// Implementations must atomically deduplicate by canonical owner and content,
/// reserve the reference, and publish the complete record. A candidate collision
/// must never overwrite anything. An identical existing registration is returned
/// even at capacity or when its newly proposed candidate collides elsewhere.
/// A successful lookup never changes meaning during the store's lifetime.
/// Durable adapters must commit before success; ambiguous infrastructure failures
/// can be retried with a fresh proof and deduplicated. Do not reuse this store
/// across AS namespaces. No positive grant authorization is implied by a lookup.
pub trait ResourceSetStore {
    /// Finds a public reference; a missing record is not an authorization grant.
    /// # Errors
    /// Returns an error if storage cannot make a reliable lookup.
    fn lookup(&self, reference: &str) -> Result<Option<ResourceSet>, ResourceSetError>;

    /// Registers understood, authorized leaf rights or returns the existing set.
    ///
    /// Canonical content disregards the order and repetition of outer rights and
    /// JSON object keys only. Inner arrays, strings and URI spelling stay exact.
    /// Inputs must already have passed the deployment's ownership policy.
    /// Report rights count, JSON shape and serialized-rights budget failures as
    /// [`ResourceSetError::InvalidAccessInput`], not retryable unavailability.
    /// Invalid trusted owner/candidate metadata or a record budget insufficient
    /// for that metadata is [`ResourceSetError::Invalid`].
    /// # Errors
    /// Refuses collision, exhausted budgets, invalid input or unavailable storage.
    fn register_or_get(
        &self,
        owner: &RsId,
        candidate: &str,
        access: &[AccessItem],
    ) -> Result<ResourceSet, ResourceSetError>;
}

/// Bounded, single-process volatile registry with atomic insertion/deduplication.
///
/// Restart loses all references. There is deliberately no eviction or mutation;
/// applications must re-register before new grants and document this limitation.
/// The configured caps bound retained records; callers must separately bound
/// concurrent requests. A poisoned lock fails closed.
#[derive(Debug)]
pub struct MemoryResourceSetStore {
    limits: ResourceSetLimits,
    records: Mutex<HashMap<String, ResourceSet>>,
}

impl MemoryResourceSetStore {
    /// Creates an empty registry. Zero capacities refuse all new registrations.
    #[must_use]
    pub fn new(limits: ResourceSetLimits) -> Self {
        Self {
            limits,
            records: Mutex::new(HashMap::new()),
        }
    }
}

impl ResourceSetStore for MemoryResourceSetStore {
    fn lookup(&self, reference: &str) -> Result<Option<ResourceSet>, ResourceSetError> {
        let records = self
            .records
            .lock()
            .map_err(|_| ResourceSetError::Unavailable)?;
        Ok(records.get(reference).cloned())
    }

    fn register_or_get(
        &self,
        owner: &RsId,
        candidate: &str,
        access: &[AccessItem],
    ) -> Result<ResourceSet, ResourceSetError> {
        let limits = self.limits;
        if owner.0.is_empty()
            || owner.0.len() > limits.max_reference_bytes
            || candidate.is_empty()
            || candidate.len() > limits.max_reference_bytes
        {
            return Err(ResourceSetError::Invalid);
        }
        let remaining = limits
            .max_record_bytes
            .checked_sub(owner.0.len())
            .and_then(|remaining| remaining.checked_sub(candidate.len()))
            .ok_or(ResourceSetError::Invalid)?;
        if access.is_empty() || access.len() > limits.max_access_items {
            return Err(ResourceSetError::InvalidAccessInput);
        }
        let mut nodes = limits.max_json_nodes;
        for right in access {
            if let AccessItem::Described(object) = right {
                for value in object.extra.values() {
                    check_json(value, limits.max_json_depth, &mut nodes)?;
                }
            }
        }
        serde_json::to_writer(ByteBudget(remaining), access)
            .map_err(|_| ResourceSetError::InvalidAccessInput)?;
        let access = canonical_access(access)?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| ResourceSetError::Unavailable)?;
        if let Some(record) = records
            .values()
            .find(|record| record.owner == *owner && record.access == access)
        {
            return Ok(record.clone());
        }
        if records.contains_key(candidate) {
            return Err(ResourceSetError::Collision);
        }
        if records.len() >= limits.max_sets
            || records
                .values()
                .filter(|record| record.owner == *owner)
                .count()
                >= limits.max_sets_per_owner
        {
            return Err(ResourceSetError::Capacity);
        }
        let record = ResourceSet {
            reference: candidate.into(),
            owner: owner.clone(),
            access,
        };
        records.insert(candidate.into(), record.clone());
        drop(records);
        Ok(record)
    }
}

fn check_json(
    value: &serde_json::Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ResourceSetError> {
    *nodes = nodes
        .checked_sub(1)
        .ok_or(ResourceSetError::InvalidAccessInput)?;
    let depth = depth
        .checked_sub(1)
        .ok_or(ResourceSetError::InvalidAccessInput)?;
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                check_json(value, depth, nodes)?;
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                check_json(value, depth, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct ByteBudget(usize);
impl io::Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("resource budget exceeded"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn canonical_access(access: &[AccessItem]) -> Result<Vec<AccessItem>, ResourceSetError> {
    let mut rights = access
        .iter()
        .map(|right| {
            // Sorting object keys is explicit even when serde_json's preserve_order
            // feature is enabled by another workspace consumer.
            let mut value =
                serde_json::to_value(right).map_err(|_| ResourceSetError::InvalidAccessInput)?;
            sort_objects(&mut value);
            let key =
                serde_json::to_vec(&value).map_err(|_| ResourceSetError::InvalidAccessInput)?;
            Ok((key, right.clone()))
        })
        .collect::<Result<Vec<_>, ResourceSetError>>()?;
    rights.sort_by(|left, right| left.0.cmp(&right.0));
    rights.dedup_by(|left, right| left.0 == right.0);
    Ok(rights.into_iter().map(|(_, right)| right).collect())
}

fn sort_objects(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.sort_keys();
            for value in map.values_mut() {
                sort_objects(value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                sort_objects(value);
            }
        }
        _ => {}
    }
}
