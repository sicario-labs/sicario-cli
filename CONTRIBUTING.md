# Contributing to Sicario CLI

Thanks for your interest in contributing! This guide will help you get started.

## Getting started

1. Fork the repository and clone your fork
2. Install Rust 1.75+ (stable): https://rustup.rs
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

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Make your changes with clear, focused commits
3. Ensure all tests pass: `cargo test --workspace`
4. Run clippy: `cargo clippy --workspace -- -D warnings`
5. Format your code: `cargo fmt --all`
6. Open a pull request against `main`

## Code style

- Follow standard Rust conventions and idioms
- Run `cargo fmt` before committing
- All public items should have doc comments
- New modules should include unit tests
- Property-based tests (proptest) are encouraged for core logic

## Adding security rules

Security rules live in `sicario-cli/rules/<language>/` as YAML files. Drop a file in and it's picked up automatically.

1. Create a YAML file in the appropriate language directory
2. Follow the existing rule format (see any file in `rules/` for examples)
3. Include at least 3 true-positive and 3 true-negative test cases in the YAML
4. Validate your rule: `cargo run -- rules validate`
5. Run the test harness: `cargo run -- rules test`
6. Test against samples: `sicario scan .` (scans the current directory by default)

> **Tip:** Running `sicario` with no arguments scans the current directory, so you can also just run `sicario` from the repo root to test your rule against the included samples.

## Working on the Convex backend

The cloud backend lives in `convex/convex/` and is deployed to Convex. The frontend (`sicario-frontend/`) consumes these functions.

1. Install Node.js 18+ and run `npm install` in the `convex/` directory
2. Copy `.env.local.example` to `.env.local` and set your `CONVEX_DEPLOYMENT`
3. Run `npx convex dev` to start the dev server with hot reload
4. Schema changes go in `convex/convex/schema.ts`
5. After modifying backend functions, sync to the frontend: copy updated files from `convex/convex/` to `sicario-frontend/convex/`
6. Run `npm run build` in `sicario-frontend/` to verify the frontend compiles

> **Important:** The `convex/convex/` directory is the source of truth. Always edit there first, then sync to `sicario-frontend/convex/`.

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

- Keep PRs focused — one feature or fix per PR
- Include a clear description of what changed and why
- Add tests for new functionality
- Update documentation if the public API changes
- Link related issues using `Closes #123` or `Fixes #123`

## Reporting bugs

Open an issue with:
- Sicario version (`sicario --version`)
- OS and architecture
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output (run with `RUST_LOG=debug`)

## Security vulnerabilities

Please do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
