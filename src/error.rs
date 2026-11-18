//! The one error type. Its kinds are the error table in docs/api.md.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    InvalidParams,
    MethodNotFound,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    SandboxUnavailable,
    TooLarge,
    Io,
}

impl ErrorKind {
    pub const ALL: [ErrorKind; 8] = [
        ErrorKind::InvalidParams,
        ErrorKind::MethodNotFound,
        ErrorKind::NotFound,
        ErrorKind::AlreadyExists,
        ErrorKind::PermissionDenied,
        ErrorKind::SandboxUnavailable,
        ErrorKind::TooLarge,
        ErrorKind::Io,
    ];

    /// The JSON-RPC `code` and `data.kind` of this kind, as in api.md's error table.
    const fn wire(self) -> (i64, &'static str) {
        match self {
            ErrorKind::InvalidParams => (-32602, "invalid_params"),
            ErrorKind::MethodNotFound => (-32601, "method_not_found"),
            ErrorKind::NotFound => (-32004, "not_found"),
            ErrorKind::AlreadyExists => (-32009, "already_exists"),
            ErrorKind::PermissionDenied => (-32003, "permission_denied"),
            ErrorKind::SandboxUnavailable => (-32010, "sandbox_unavailable"),
            ErrorKind::TooLarge => (-32013, "too_large"),
            ErrorKind::Io => (-32000, "io"),
        }
    }

    pub const fn code(self) -> i64 {
        self.wire().0
    }

    pub const fn as_str(self) -> &'static str {
        self.wire().1
    }

    pub fn from_name(kind: &str) -> Option<ErrorKind> {
        ErrorKind::ALL.into_iter().find(|k| k.as_str() == kind)
    }
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let kind = String::deserialize(d)?;
        ErrorKind::from_name(&kind)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown error kind `{kind}`")))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Error {
        Error {
            kind,
            message: message.into(),
        }
    }

    pub fn invalid_params(message: impl Into<String>) -> Error {
        Error::new(ErrorKind::InvalidParams, message)
    }

    pub fn not_found(message: impl Into<String>) -> Error {
        Error::new(ErrorKind::NotFound, message)
    }

    pub fn sandbox_unavailable(message: impl Into<String>) -> Error {
        Error::new(ErrorKind::SandboxUnavailable, message)
    }

    pub fn too_large(message: impl Into<String>) -> Error {
        Error::new(ErrorKind::TooLarge, message)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        let kind = match err.kind() {
            std::io::ErrorKind::NotFound => ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
            std::io::ErrorKind::AlreadyExists => ErrorKind::AlreadyExists,
            _ => ErrorKind::Io,
        };
        Error::new(kind, err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_have_the_codes_of_the_api_table() {
        let table: Vec<(i64, &str)> = ErrorKind::ALL
            .iter()
            .map(|k| (k.code(), k.as_str()))
            .collect();
        assert_eq!(
            table,
            [
                (-32602, "invalid_params"),
                (-32601, "method_not_found"),
                (-32004, "not_found"),
                (-32009, "already_exists"),
                (-32003, "permission_denied"),
                (-32010, "sandbox_unavailable"),
                (-32013, "too_large"),
                (-32000, "io"),
            ]
        );
    }

    #[test]
    fn kind_names_round_trip() {
        for kind in ErrorKind::ALL {
            assert_eq!(ErrorKind::from_name(kind.as_str()), Some(kind));
        }
        assert_eq!(ErrorKind::from_name("nope"), None);
    }

    #[test]
    fn error_serializes_as_kind_and_message() {
        let err = Error::new(ErrorKind::TooLarge, "17 MiB");
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "kind": "too_large", "message": "17 MiB" })
        );
        assert_eq!(serde_json::from_value::<Error>(json).unwrap(), err);
    }

    #[test]
    fn io_errors_map_to_kinds() {
        let kind = |k| Error::from(std::io::Error::from(k)).kind;
        assert_eq!(kind(std::io::ErrorKind::NotFound), ErrorKind::NotFound);
        assert_eq!(
            kind(std::io::ErrorKind::PermissionDenied),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            kind(std::io::ErrorKind::AlreadyExists),
            ErrorKind::AlreadyExists
        );
        assert_eq!(kind(std::io::ErrorKind::BrokenPipe), ErrorKind::Io);
        let err = Error::from(std::io::Error::other("disk on fire"));
        assert_eq!(err, Error::new(ErrorKind::Io, "disk on fire"));
    }
}
