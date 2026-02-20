# Contributing

Thank you for your interest in contributing to Internet Scanners OSINT Tool!

## How to contribute

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```
3. **Install dev dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```
4. **Make your changes** and write tests if applicable
5. **Run the tests**:
   ```bash
   make test
   ```
6. **Lint your code**:
   ```bash
   make lint
   ```
7. **Commit** with a clear message describing the change
8. **Open a Pull Request** against `main`

## Code style

- Follow PEP 8 conventions
- Use type hints where practical
- Keep functions focused and well-documented

## Reporting bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) when opening an issue.

## Suggesting features

Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md).
