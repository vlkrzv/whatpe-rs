# WhatPE (Rust)

A ground-up Rust rewrite of [WhatPE](https://github.com/vlkrzv/WhatPE), a Windows utility that
shows PE (Portable Executable) build metadata for EXE/DLL files — actual compile timestamp,
Debug/Release build mode, bitness, compiler/Visual Studio toolset version, target .NET Framework
version, and security mitigations (DEP/ASLR/CFG) — via a right-click "What PE?" context-menu
entry in Explorer.

**Status: early work in progress, not yet functional.** This rewrite exists for two reasons: to
replace the original's hand-rolled C++ PE parsing (which reads untrusted binaries) with
[`goblin`](https://github.com/m4b/goblin), a memory-safe Rust parser designed for exactly that
threat model, and as a Rust learning project.

## Workspace layout

- `crates/whatpe-core` — PE parsing and build-metadata extraction. No OS dependency; operates on
  a byte slice.
- `crates/whatpe-cli` — command-line viewer.
- `crates/whatpe-dialog` (planned) — native Win32 dialog shown from the Explorer context menu.
- `crates/whatpe-shell` (planned) — `IExplorerCommand` COM server providing the right-click
  "What PE?" entry.

## License

MIT — see [LICENSE](LICENSE).
