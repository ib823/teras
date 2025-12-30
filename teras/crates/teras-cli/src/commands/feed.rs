//! Feed commands.

use clap::{Args, Subcommand};
use colored::Colorize;
use teras_core::error::TerasResult;
use teras_integrasi::TerasContext;

/// Feed command arguments.
#[derive(Args)]
pub struct FeedArgs {
    #[command(subcommand)]
    pub command: FeedCommands,
}

#[derive(Subcommand)]
pub enum FeedCommands {
    /// List registered feed sources
    List,

    /// Fetch indicators from all feeds
    FetchAll,

    /// Fetch indicators from a specific feed
    Fetch {
        /// Feed source ID
        source: String,
    },

    /// Search stored indicators
    Search {
        /// Search query
        query: String,

        /// Maximum results
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },

    /// Show indicator statistics
    Stats,
}

/// Execute feed command.
pub async fn execute(args: FeedArgs, verbose: bool) -> TerasResult<()> {
    let ctx = TerasContext::new_in_memory();

    match args.command {
        FeedCommands::List => {
            println!("{}", "Registered Feed Sources".green().bold());
            println!();

            for source_id in ctx.feeds().source_ids() {
                println!("  - {}", source_id);
            }

            Ok(())
        }

        FeedCommands::FetchAll => {
            println!("{}", "Fetching all feeds...".yellow());

            match ctx.feeds().fetch_all().await {
                Ok(result) => {
                    println!();
                    println!("{}", "Fetch Complete".green().bold());
                    println!("  Indicators fetched: {}", result.indicators_fetched);
                    println!("  Indicators stored:  {}", result.indicators_stored);
                    println!("  Duration:           {}ms", result.duration_ms);

                    if verbose {
                        println!();
                        println!("Audit log entries: {}", ctx.audit().count()?);
                    }

                    Ok(())
                }
                Err(e) => {
                    println!("{} {}", "Fetch failed:".red(), e);
                    Err(e)
                }
            }
        }

        FeedCommands::Fetch { source } => {
            println!("Fetching from {}...", source.cyan());

            match ctx.feeds().fetch_source(&source).await {
                Ok(result) => {
                    println!();
                    println!("{}", "Fetch Complete".green().bold());
                    println!("  Indicators fetched: {}", result.indicators_fetched);
                    println!("  Indicators stored:  {}", result.indicators_stored);
                    println!("  Duration:           {}ms", result.duration_ms);
                    Ok(())
                }
                Err(e) => {
                    println!("{} {}", "Fetch failed:".red(), e);
                    Err(e)
                }
            }
        }

        FeedCommands::Search { query, limit } => {
            println!("Searching for '{}'...", query.cyan());
            println!();

            let results = ctx.feeds().search(&query, limit)?;

            if results.is_empty() {
                println!("{}", "No results found.".yellow());
            } else {
                println!("{} {} results:", "Found".green(), results.len());
                println!();

                for indicator in results {
                    println!(
                        "  {} {} [{}]",
                        indicator.indicator_type.to_string().cyan(),
                        indicator.value,
                        indicator.source.dimmed()
                    );
                }
            }

            Ok(())
        }

        FeedCommands::Stats => {
            let count = ctx.feeds().indicator_count()?;

            println!("{}", "Indicator Statistics".green().bold());
            println!();
            println!("  Total indicators: {}", count);
            println!("  Sources: {}", ctx.feeds().source_ids().len());

            Ok(())
        }
    }
}
