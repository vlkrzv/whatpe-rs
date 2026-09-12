#[derive(Debug, thiserror::Error)]
pub enum PeInfoError {
    #[error("failed to parse PE file: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("not a PE32/PE32+ image (missing optional header)")]
    MissingOptionalHeader,
}
