#![forbid(unsafe_code)]

pub fn scaffold_message() -> &'static str {
    "whatpe-core scaffold -- PE parsing lands in Phase 2"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_message_is_not_empty() {
        assert!(!scaffold_message().is_empty());
    }
}
