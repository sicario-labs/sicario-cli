# Contributing to Sicario

Thank you for your interest in contributing. This document covers everything you need to get started.

## Getting started

1. Fork the repository and clone your fork
2. Install Rust 1.75+ stable: https://rustup.rs
3. On Linux, install system dependencies:
   ```bash
   sudo apt-get install -y libsecret-1-dev pkg-config
   ```
4. Build and run tests:
   ```bash
   cargo build
   cargo test --workspace
   ```

## Development workflow

```bash
git checkout -b feat/my-feature   # branch from main
# make changes
cargo test --workspace            # all tests must pass
cargo clippy --workspace -- -D warnings
cargo fmt --all
# open a pull request against main
```

## Code style

- Follow standard Rust conventions
- Run `cargo fmt` before committing
- Public items should have doc comments
- New modules should include unit tests
- Property-based tests (proptest) are encouraged for core logic

## Adding security rules

Rules live in `sicario-cli/rules/<language>/` as YAML files. Drop a file in and it's picked up automatically.

1. Create a YAML file in the appropriate language directory
2. Follow the format of existing rules (see any file in `rules/` for examples)
3. Include at least 3 true-positive and 3 true-negative test cases
4. Validate: `cargo run -- rules validate`
5. Test: `cargo run -- rules test`

To verify your rule fires correctly against a real vulnerable file, use the **vulnerability sandbox**:

```bash
# Add a vulnerable test file to vuln-sandbox/ and scan it
sicario scan vuln-sandbox/node/cwe-89/
```

See [`vuln-sandbox/README.md`](vuln-sandbox/README.md) for the full sandbox structure.

## Working on the Convex backend

The cloud backend lives in `convex/convex/`. The frontend (`sicario-frontend/`) consumes these functions.

1. Install Node.js 18+ and run `npm install` in `convex/`
2. Set `CONVEX_DEPLOYMENT` in `convex/.env.local`
3. Run `npx convex dev` for hot reload
4. Schema changes go in `convex/convex/schema.ts`

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add LDAP injection detection for Go
fix: correct false positive in Python SQL injection rule
docs: update CLI reference in README
test: add property tests for confidence scorer
chore: bump tree-sitter to 0.21
```

## Pull request guidelines

- One feature or fix per PR
- Clear description of what changed and why
- Tests for new functionality
- Documentation updated if the public API changes
- Link related issues with `Closes #123`

## Reporting bugs

Open an issue with:
- Sicario version (`sicario --version`)
- OS and architecture
- Steps to reproduce
- Expected vs actual behavior
- Log output (`RUST_LOG=debug sicario scan .`)

## Security vulnerabilities

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md).

## Contributor License Agreement

By submitting a pull request, you agree to the [Contributor License Agreement](CLA.md). All contributions must be covered by the CLA before they can be merged.

The CLA grants the Licensor (Emmanuel Enyi) a perpetual, irrevocable, worldwide, royalty-free license to use, modify, sublicense, and relicense your contributions under any license, including the FSL-1.1 and any future open-source license (such as Apache 2.0 upon the Change Date). You retain copyright to your contributions.

If you have not yet signed the CLA, please review [CLA.md](CLA.md) and indicate your agreement by adding your name to the CLA signatories list in your pull request description.

## Contributing Rules

To contribute detection rules to the community rule library, see the `sicario-rules` repository (Apache 2.0). That repository accepts YAML rule files and test fixtures — no Rust source code required.

## License

Sicario is licensed under the [Functional Source License 1.1](LICENSE) (FSL-1.1). Contributions are accepted under the terms of the CLA described above.
