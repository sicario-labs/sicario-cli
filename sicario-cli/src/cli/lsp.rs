//! LSP subcommand arguments.

use clap::Parser;

/// Arguments for the `lsp` subcommand.
///
/// The LSP server communicates over stdin/stdout using JSON-RPC,
/// so no additional flags are needed.
#[derive(Parser, Debug)]
pub struct LspArgs;
