use gnap_types::access::{AccessItem, AccessObject};

use crate::{Error, PROFILE};

/// The two operations in this file profile. Methods are case-sensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAction {
    /// Read one resource with GET.
    Read,
    /// Replace one resource with PUT.
    Write,
}

impl FileAction {
    /// The action name used in access descriptions and authority facts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            _ => Err(Error::Profile),
        }
    }
}

/// One exact resource/action pair; separate pairs never form a cross-product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRight {
    resource: String,
    action: FileAction,
}

impl FileRight {
    /// Constructs an exact HTTP(S) URI right, without normalization.
    ///
    /// # Errors
    /// Rejects invalid, fragment-bearing, credential-bearing or oversized URIs.
    pub fn new(resource: String, action: FileAction) -> Result<Self, Error> {
        validate_uri(&resource)?;
        Ok(Self { resource, action })
    }

    /// The exact resource URI.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// The allowed operation.
    #[must_use]
    pub const fn action(&self) -> FileAction {
        self.action
    }
}

impl TryFrom<&AccessItem> for FileRight {
    type Error = Error;

    fn try_from(value: &AccessItem) -> Result<Self, Error> {
        let AccessItem::Described(value) = value else {
            return Err(Error::Profile);
        };
        if value.kind != PROFILE
            || value.identifier.is_some()
            || value.datatypes.is_some()
            || value.privileges.is_some()
            || !value.extra.is_empty()
        {
            return Err(Error::Profile);
        }
        let (Some(locations), Some(actions)) = (&value.locations, &value.actions) else {
            return Err(Error::Profile);
        };
        let ([resource], [action]) = (locations.as_slice(), actions.as_slice()) else {
            return Err(Error::Profile);
        };
        Self::new(resource.clone(), FileAction::parse(action)?)
    }
}

impl From<&FileRight> for AccessItem {
    fn from(value: &FileRight) -> Self {
        Self::Described(Box::new(AccessObject {
            kind: PROFILE.into(),
            locations: Some(vec![value.resource.clone()]),
            actions: Some(vec![value.action.as_str().into()]),
            ..AccessObject::default()
        }))
    }
}

pub(crate) fn validate_uri(value: &str) -> Result<(), Error> {
    let authority = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .and_then(|rest| rest.split(['/', '?']).next())
        .ok_or(Error::Profile)?;
    if value.len() > 2048
        || authority.is_empty()
        || authority.contains('@')
        || !gnap_types::uri::is_absolute(value)
    {
        return Err(Error::Profile);
    }
    Ok(())
}
