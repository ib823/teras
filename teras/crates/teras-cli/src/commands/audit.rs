//! Audit commands.

use clap::{Args, Subcommand};
use colored::Colorize;
use teras_core::error::TerasResult;
use teras_integrasi::TerasContext;

/// Audit command arguments.
#[derive(Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommands,
}

#[derive(Subcommand)]
pub enum AuditCommands {
    /// Verify audit chain integrity
    Verify,

    /// Show audit log statistics
    Stats,

    /// List recent audit entries
    List {
        /// Number of entries to show
        #[arg(short, long, default_value = "10")]
        count: u64,
    },
}

/// Execute audit command.
#[allow(clippy::cast_possible_truncation)]
pub async fn execute(args: AuditArgs, verbose: bool) -> TerasResult<()> {
    let ctx = TerasContext::new_in_memory();

    match args.command {
        AuditCommands::Verify => {
            println!("{}", "Verifying audit chain...".yellow());

            let result = ctx
                .audit()
                .verify_chain()
                .map_err(|e| teras_core::error::TerasError::InvalidFormat(e.to_string()))?;

            println!();
            if result.valid {
                println!("{}", "Audit chain is VALID".green().bold());
                println!("  Entries verified: {}", result.entries_verified);
            } else {
                println!("{}", "Audit chain is CORRUPTED".red().bold());
                if let Some(index) = result.first_error_at {
                    println!("  Corruption at entry: {}", index);
                }
                if let Some(reason) = &result.error_description {
                    println!("  Reason: {}", reason);
                }
            }

            Ok(())
        }

        AuditCommands::Stats => {
            let log = ctx.audit();
            let count = log.count()?;

            println!("{}", "Audit Log Statistics".green().bold());
            println!();
            println!("  Total entries: {}", count);

            let chain_valid = log.verify_chain().map(|r| r.valid).unwrap_or(false);

            println!(
                "  Chain status:  {}",
                if chain_valid {
                    "Valid".green()
                } else {
                    "Corrupted".red()
                }
            );

            if verbose {
                if let Ok(Some(last)) = log.last() {
                    if let Some(hash) = last.entry_hash {
                        println!("  Last hash:     {:02x?}", &hash[..8]);
                    }
                }
            }

            Ok(())
        }

        AuditCommands::List { count } => {
            println!("{}", "Recent Audit Entries".green().bold());
            println!();

            let log = ctx.audit();
            let total = log.count()?;

            if total == 0 {
                println!("{}", "No audit entries yet.".yellow());
                return Ok(());
            }

            let start = if total > count { total - count + 1 } else { 1 };

            for i in start..=total {
                if let Ok(Some(entry)) = log.get(i) {
                    println!(
                        "  [{}] {} - {:?}",
                        entry.event_id,
                        entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        entry.action
                    );
                }
            }

            Ok(())
        }
    }
}
