

## Codely Structured Memories

### User

### Feedback

### Project
- [2026-07-31 09:29:08] [project] AI Sandbox project: prevents AI hallucination from writing/deleting files outside workspace. Uses OS-native sandbox (no injection/hooks). Windows: Restricted Token + ACL. Linux: Landlock LSM. macOS: deferred (sandbox-exec/Seatbelt planned). Cross-platform refactor completed 2026-07-31.
- [2026-07-31 12:17:32] Open-source preparation completed 2026-07-31. License: Apache-2.0 (user chose over MIT for patent protection and enterprise friendliness). Added: LICENSE, .gitignore, DESIGN.md (replaced outdated 需求文档.txt), CONTRIBUTING.md, CHANGELOG.md, GitHub Actions CI (Windows+Linux), integration tests (4 cases via ctest), SPDX headers on all source files. Fixed build_project.bat hardcoded VS path → vswhere auto-detection. README updated with badges.

### Reference

