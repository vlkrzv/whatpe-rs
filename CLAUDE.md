# whatpe-rs — Notes for Claude

## Verify current versions before pinning

Don't rely on recalled defaults for any pinned version, tool, or library usage — they may be
stale (this repo already hit this with `edition = "2021"` and `actions/checkout@v4`). Check
upstream (crates.io, `gh api repos/<owner>/<repo>/releases/latest`, the tool's own docs) before
pinning or bumping. Check release notes for breaking changes first — staying a version behind
deliberately is fine; the point is an informed choice, not a stale one.
