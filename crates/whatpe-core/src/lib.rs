#![forbid(unsafe_code)]

mod detect;
mod error;

pub use error::PeInfoError;

use goblin::pe::PE;

pub struct PeFileInfo {
    pub categories: Vec<Category>,
}

pub struct Category {
    pub name: String,
    pub items: Vec<Item>,
}

pub struct Item {
    pub name: String,
    pub value: String,
    pub note: Option<String>,
}

impl Item {
    fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Item {
            name: name.into(),
            value: value.into(),
            note: None,
        }
    }

    fn with_note(
        name: impl Into<String>,
        value: impl Into<String>,
        note: impl Into<String>,
    ) -> Self {
        Item {
            name: name.into(),
            value: value.into(),
            note: Some(note.into()),
        }
    }
}

/// Parses PE build metadata out of `bytes`. Takes a byte slice rather than a file path so this
/// crate has no OS dependency: callers own reading the file (or mapping it, or embedding a test
/// fixture) and hand over the bytes.
pub fn analyze(bytes: &[u8]) -> Result<PeFileInfo, PeInfoError> {
    let pe = PE::parse(bytes)?;
    let optional_header = pe
        .header
        .optional_header
        .ok_or(PeInfoError::MissingOptionalHeader)?;

    let mut categories = vec![detect::build_category(&pe, &optional_header)];

    if pe.clr_data.is_some() {
        categories.push(detect::dotnet_category());
    }

    categories.push(detect::security_category(&optional_header));

    Ok(PeFileInfo { categories })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_rejects_garbage_bytes() {
        let result = analyze(b"not a PE file");
        assert!(result.is_err());
    }

    /// No fixture binary is committed to the repo; the test binary running this test is itself
    /// a real PE file (this whole workspace only targets Windows), so reading it back from disk
    /// gives an always-available, always-current real-world sample for free.
    #[test]
    fn analyze_parses_own_test_binary() {
        let own_path = std::env::current_exe().expect("current_exe should be available");
        let bytes = std::fs::read(own_path).expect("should be able to read own test binary");

        let info = analyze(&bytes).expect("own test binary should parse as a valid PE file");

        let category_names: Vec<&str> = info.categories.iter().map(|c| c.name.as_str()).collect();
        assert!(category_names.contains(&"Build"));
        assert!(category_names.contains(&"Security"));

        let build_category = info
            .categories
            .iter()
            .find(|c| c.name == "Build")
            .expect("Build category should be present");
        let item_names: Vec<&str> = build_category
            .items
            .iter()
            .map(|item| item.name.as_str())
            .collect();
        assert!(item_names.contains(&"Toolset"));
    }
}
