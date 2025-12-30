//! Initialize TERAS command.

use clap::Args;
use colored::Colorize;
use teras_core::error::TerasResult;

/// Initialize TERAS arguments.
#[derive(Args)]
pub struct InitArgs {
    /// Data directory for storage
    #[arg(short, long, default_value = "./teras-data")]
    pub data_dir: String,
}

/// Execute init command.
pub async fn execute(args: InitArgs) -> TerasResult<()> {
    println!("{}", "TERAS Initialization".green().bold());
    println!();
    println!("Data directory: {}", args.data_dir);

    // Create directory structure
    std::fs::create_dir_all(&args.data_dir).map_err(|e| {
        teras_core::error::TerasError::ConfigurationError {
            component: "init".to_string(),
            message: format!("Failed to create data directory: {}", e),
        }
    })?;

    std::fs::create_dir_all(format!("{}/audit", args.data_dir)).ok();
    std::fs::create_dir_all(format!("{}/indicators", args.data_dir)).ok();
    std::fs::create_dir_all(format!("{}/keys", args.data_dir)).ok();

    println!();
    println!("{}", "Directory structure created:".green());
    println!("  {}/audit/       - Audit logs", args.data_dir);
    println!("  {}/indicators/  - Threat indicators", args.data_dir);
    println!("  {}/keys/        - Key storage", args.data_dir);
    println!();
    println!("{}", "TERAS initialized successfully!".green().bold());

    Ok(())
}
