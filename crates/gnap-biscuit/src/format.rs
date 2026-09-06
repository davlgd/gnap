use std::collections::{BTreeMap, HashSet};

use base64::{
    alphabet,
    engine::{
        general_purpose::{GeneralPurpose, GeneralPurposeConfig},
        DecodePaddingMode,
    },
    Engine,
};
use biscuit_auth::{datalog::SymbolTable, format::schema};
use gnap_types::token::TokenValue;
use prost::Message;
use serde_json::{Map, Value};

use crate::{rights::validate_uri, Error, FileAction, FileRight, PROFILE};

const MAX_BYTES: usize = 16 * 1024;
const MAX_BLOCKS: usize = 16;

/// Unauthenticated structural information. Never use it as an access decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inspection {
    /// Decoded binary length, at most 16 KiB.
    pub decoded_bytes: usize,
    /// Total blocks, including the authority, at most 16.
    pub blocks: usize,
    /// Claimed root key ID, to be resolved from local configuration only.
    pub root_key_id: u32,
}

/// Decodes and checks the restricted grammar without signature verification or
/// Datalog evaluation.
///
/// Suitable for rejecting unsupported work before admission
/// to a bounded worker; it does not make decoding a hard-preemptible operation.
///
/// # Errors
/// Rejects oversized encodings, malformed protobuf, unsupported facts/checks,
/// nested terms, arbitrary expressions, rules, scopes and third-party blocks.
pub fn inspect(value: &TokenValue) -> Result<Inspection, Error> {
    Ok(parse(value)?.info)
}

pub(crate) struct Parsed {
    pub(crate) bytes: Vec<u8>,
    pub(crate) info: Inspection,
    pub(crate) claims: Claims,
}

pub(crate) struct Claims {
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) jwk: Map<String, Value>,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) deadline: u64,
}

pub(crate) fn parse(value: &TokenValue) -> Result<Parsed, Error> {
    if value.as_str().len() > MAX_BYTES.div_ceil(3) * 4 {
        return Err(Error::Profile);
    }
    let engine = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let bytes = engine.decode(value.as_str()).map_err(|_| Error::Profile)?;
    if bytes.len() > MAX_BYTES {
        return Err(Error::Profile);
    }
    let envelope = schema::Biscuit::decode(bytes.as_slice()).map_err(|_| Error::Profile)?;
    let count = 1 + envelope.blocks.len();
    if count > MAX_BLOCKS {
        return Err(Error::Profile);
    }
    let info = Inspection {
        decoded_bytes: bytes.len(),
        blocks: count,
        root_key_id: envelope.root_key_id.ok_or(Error::Profile)?,
    };
    let mut symbols = SymbolTable::new();
    let mut total_symbols = 0;
    let mut claims = None;
    for (index, signed) in std::iter::once(&envelope.authority)
        .chain(&envelope.blocks)
        .enumerate()
    {
        if signed.external_signature.is_some() {
            return Err(Error::Profile);
        }
        let block = schema::Block::decode(signed.block.as_slice()).map_err(|_| Error::Profile)?;
        total_symbols += block.symbols.len();
        if block.version != Some(3)
            || block.context.is_some()
            || !block.rules.is_empty()
            || !block.scope.is_empty()
            || !block.public_keys.is_empty()
            || total_symbols > 128
            || block.symbols.iter().any(|s| s.len() > 4096)
            || block.symbols.iter().collect::<HashSet<_>>().len() != block.symbols.len()
        {
            return Err(Error::Profile);
        }
        symbols
            .extend(&SymbolTable::from(block.symbols.clone()).map_err(|_| Error::Profile)?)
            .map_err(|_| Error::Profile)?;
        if index == 0 {
            claims = Some(authority(&block, &symbols)?);
        } else {
            if !block.facts.is_empty() || block.checks.is_empty() || block.checks.len() > 2 {
                return Err(Error::Profile);
            }
            for check in &block.checks {
                if let Some(deadline) = restriction(check, &symbols)? {
                    let claims = claims.as_mut().ok_or(Error::Profile)?;
                    claims.deadline = claims.deadline.min(deadline);
                }
            }
        }
    }
    Ok(Parsed {
        bytes,
        info,
        claims: claims.ok_or(Error::Profile)?,
    })
}

fn authority(block: &schema::Block, symbols: &SymbolTable) -> Result<Claims, Error> {
    if !block.checks.is_empty() || !(8..=39).contains(&block.facts.len()) {
        return Err(Error::Profile);
    }
    let mut fields = BTreeMap::new();
    let mut rights = Vec::new();
    for fact in &block.facts {
        let predicate = &fact.predicate;
        let name = symbols.get_symbol(predicate.name).ok_or(Error::Profile)?;
        if name == "right" {
            let [resource, action] = predicate.terms.as_slice() else {
                return Err(Error::Profile);
            };
            let right = FileRight::new(
                text(resource, symbols)?.into(),
                FileAction::parse(text(action, symbols)?)?,
            )?;
            if rights.contains(&right) {
                return Err(Error::Profile);
            }
            rights.push(right);
        } else {
            let [value] = predicate.terms.as_slice() else {
                return Err(Error::Profile);
            };
            if fields.insert(name, value).is_some() {
                return Err(Error::Profile);
            }
        }
    }
    if fields.len() != 7 || rights.is_empty() || rights.len() > 32 {
        return Err(Error::Profile);
    }
    let get = |name| fields.get(name).copied().ok_or(Error::Profile);
    if text(get("gnap_profile")?, symbols)? != PROFILE
        || text(get("gnap_proof")?, symbols)? != "httpsig"
    {
        return Err(Error::Profile);
    }
    let issuer = text(get("gnap_issuer")?, symbols)?.to_owned();
    let audience = text(get("gnap_audience")?, symbols)?.to_owned();
    validate_uri(&issuer)?;
    validate_uri(&audience)?;
    let jwk = serde_json::from_str(text(get("gnap_jwk")?, symbols)?).map_err(|_| Error::Profile)?;
    let issued_at = integer(get("gnap_iat")?)?;
    let expires_at = integer(get("gnap_exp")?)?;
    if issued_at >= expires_at {
        return Err(Error::Profile);
    }
    Ok(Claims {
        issuer,
        audience,
        jwk,
        issued_at,
        expires_at,
        deadline: expires_at,
    })
}

fn restriction(check: &schema::Check, symbols: &SymbolTable) -> Result<Option<u64>, Error> {
    if check.kind.unwrap_or(schema::check::Kind::One as i32) != schema::check::Kind::One as i32 {
        return Err(Error::Profile);
    }
    let [query] = check.queries.as_slice() else {
        return Err(Error::Profile);
    };
    if !query.scope.is_empty()
        || symbols.get_symbol(query.head.name) != Some("query")
        || !query.head.terms.is_empty()
    {
        return Err(Error::Profile);
    }
    let [predicate] = query.body.as_slice() else {
        return Err(Error::Profile);
    };
    let [term] = predicate.terms.as_slice() else {
        return Err(Error::Profile);
    };
    match symbols.get_symbol(predicate.name) {
        Some("resource") if query.expressions.is_empty() => {
            validate_uri(text(term, symbols)?)?;
            Ok(None)
        }
        Some("time") => deadline(query, term).map(Some),
        _ => Err(Error::Profile),
    }
}

fn deadline(query: &schema::Rule, term: &schema::Term) -> Result<u64, Error> {
    let Some(schema::term::Content::Variable(variable)) = term.content else {
        return Err(Error::Profile);
    };
    let [expression] = query.expressions.as_slice() else {
        return Err(Error::Profile);
    };
    let [left, right, operator] = expression.ops.as_slice() else {
        return Err(Error::Profile);
    };
    let (
        Some(schema::op::Content::Value(left)),
        Some(schema::op::Content::Value(right)),
        Some(schema::op::Content::Binary(operator)),
    ) = (&left.content, &right.content, &operator.content)
    else {
        return Err(Error::Profile);
    };
    if left.content != Some(schema::term::Content::Variable(variable))
        || operator.kind != schema::op_binary::Kind::LessThan as i32
        || operator.ffi_name.is_some()
    {
        return Err(Error::Profile);
    }
    integer(right)
}

fn text<'a>(term: &schema::Term, symbols: &'a SymbolTable) -> Result<&'a str, Error> {
    let Some(schema::term::Content::String(index)) = term.content else {
        return Err(Error::Profile);
    };
    symbols.get_symbol(index).ok_or(Error::Profile)
}

fn integer(term: &schema::Term) -> Result<u64, Error> {
    let Some(schema::term::Content::Integer(value)) = term.content else {
        return Err(Error::Profile);
    };
    u64::try_from(value).map_err(|_| Error::Profile)
}
