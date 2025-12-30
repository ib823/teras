//! TERAS Command-Line Interface
//!
//! Provides commands for REALITY 6 daily workflow.

use clap::{Parser, Subcommand};
use colored::Colorize;

mod commands;

use commands::{audit, crypto, feed, init, sandi};

/// TERAS Security Platform CLI
#[derive(Parser)]
#[command(name = "teras")]
#[command(author = "TERAS Team")]
#[command(version)]
#[command(about = "TERAS Security Platform - Command Line Interface")]
#[command(long_about = r#"
TERAS Security Platform CLI

Implements REALITY 6: Daily threat intelligence workflow
  - Fetch: Download latest indicators from external feeds
  - Review: Examine fetched indicators
  - Deploy: Push to TERAS (storage)

LAW 8 Compliance: All operations are audit logged.
"#)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize TERAS
    Init(init::InitArgs),

    /// Threat feed operations
    Feed(feed::FeedArgs),

    /// Audit log operations
    Audit(audit::AuditArgs),

    /// Cryptographic operations
    Crypto(crypto::CryptoArgs),

    /// Digital signature operations
    Sandi(sandi::SandiArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init(args) => init::execute(args).await,
        Commands::Feed(args) => feed::execute(args, cli.verbose).await,
        Commands::Audit(args) => audit::execute(args, cli.verbose).await,
        Commands::Crypto(args) => crypto::execute(args, cli.verbose).await,
        Commands::Sandi(args) => sandi::execute(args, cli.verbose).await,
    };

    if let Err(e) = result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}
