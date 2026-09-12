# whatpe-rs — Notes for Claude

## Verify current versions before pinning anything

LLM training data has a knowledge cutoff, so defaults recalled from memory (a Rust edition, a
GitHub Action version, a crate's latest version) can already be stale by the time you use them.
This project already hit this twice: `edition = "2021"` when 2024 was current, and
`actions/checkout@v4` when `v7` was current and `v4` was already triggering Node.js deprecation
warnings.

Before setting or bumping any of the following, check upstream rather than relying on recalled
knowledge:

- **Rust edition** — check the latest stable edition (e.g. via the Rust release notes or
  `rustc --version` / the edition guide), don't assume the edition you remember is current.
- **GitHub Actions versions** (`uses: owner/action@vN` in `.github/workflows/`) — check
  `gh api repos/<owner>/<repo>/releases/latest` (or the repo's Releases page) for the current
  major version before pinning or leaving one unbumped.
- **Crate versions** (`Cargo.toml`) — check crates.io or `cargo search <crate>` for the current
  latest version rather than assuming a remembered version number is still current.

This doesn't mean always chasing the newest release reflexively — check release notes for
breaking changes first, and it's fine to stay a version behind deliberately. The point is to
make an informed, current choice rather than an unknowingly stale one.
