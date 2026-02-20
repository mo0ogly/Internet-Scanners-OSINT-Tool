# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] - 2026-02-20

### Added
- Unit test suite with pytest (32 tests, fully mocked, with assertions)
- CI pipeline via GitHub Actions (lint + test on Python 3.9, 3.10, 3.12)
- `pyproject.toml` for modern Python packaging (PEP 621)
- `Makefile` with `test`, `lint`, `install`, `clean` targets
- Community files: CONTRIBUTING.md, SECURITY.md, CHANGELOG.md
- GitHub issue and PR templates
- `config/settings.json.example` tracked template for API keys

### Fixed
- Missing `as_completed` import in `cli_Reverse_MX_Lookup_Tool.py`
- Shebang line placed after docstring in `cli_Reverse_MX_Lookup_Tool.py`
- `parse_known_args()` silently ignoring unknown CLI arguments

### Security
- Sanitized exception logging to prevent API key leakage in tracebacks
- GitHub Actions pinned to commit SHA to prevent supply-chain attacks
- `.gitignore` hardened (`.env`, `.coverage`, `venv/`, `*.egg-info/`, IDE files)
