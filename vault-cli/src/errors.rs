//! Error handling for Vault CLI

use std::fmt;

/// CLI-specific errors
#[derive(Debug)]
pub enum CliError {
    /// Configuration error
    Config(String),
    /// Authentication error
    Auth(String),
    /// API error
    Api(String),
    /// IO error
    Io(std::io::Error),
    /// Parse error
    Parse(String),
    /// Not found
    NotFound(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Config(msg) => write!(f, "Configuration error: {}", msg),
            CliError::Auth(msg) => write!(f, "Authentication error: {}", msg),
            CliError::Api(msg) => write!(f, "API error: {}", msg),
            CliError::Io(err) => write!(f, "IO error: {}", err),
            CliError::Parse(msg) => write!(f, "Parse error: {}", msg),
            CliError::NotFound(msg) => write!(f, "Not found: {}", msg),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        CliError::Io(err)
    }
}

impl From<CliError> for anyhow::Error {
    fn from(err: CliError) -> Self {
        anyhow::Error::new(err)
    }
}

/// Result type for CLI operations
pub type CliResult<T> = Result<T, CliError>;
