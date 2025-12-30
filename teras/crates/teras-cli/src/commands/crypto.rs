//! Crypto commands.

use clap::{Args, Subcommand};
use colored::Colorize;
use teras_core::error::TerasResult;
use teras_integrasi::TerasContext;

/// Crypto command arguments.
#[derive(Args)]
pub struct CryptoArgs {
    #[command(subcommand)]
    pub command: CryptoCommands,
}

#[derive(Subcommand)]
pub enum CryptoCommands {
    /// Generate a hybrid keypair
    Keygen {
        /// Key identifier
        #[arg(short, long)]
        id: String,

        /// Key type (kem or sign)
        #[arg(short = 't', long, default_value = "kem")]
        key_type: String,
    },

    /// Hash data
    Hash {
        /// Data to hash
        data: String,

        /// Hash algorithm (sha256, sha3, blake3)
        #[arg(short, long, default_value = "blake3")]
        algorithm: String,
    },
}

/// Execute crypto command.
pub async fn execute(args: CryptoArgs, verbose: bool) -> TerasResult<()> {
    let ctx = TerasContext::new_in_memory();

    match args.command {
        CryptoCommands::Keygen { id, key_type } => {
            println!(
                "Generating {} keypair with ID: {}...",
                key_type.cyan(),
                id.cyan()
            );
            println!();

            match key_type.as_str() {
                "kem" => {
                    let pk = ctx.crypto().generate_hybrid_keypair(&id)?;

                    println!("{}", "Hybrid KEM Keypair Generated".green().bold());
                    println!("  Key ID:    {}", pk.key_id);
                    println!("  Algorithm: {}", pk.algorithm);
                }
                "sign" => {
                    let pk = ctx.crypto().generate_signing_keypair(&id)?;

                    println!("{}", "Hybrid Signing Keypair Generated".green().bold());
                    println!("  Key ID:         {}", pk.key_id);
                    println!("  Algorithm:      {}", pk.algorithm);
                    println!("  Dilithium PK:   {} bytes", pk.dilithium_pk_size);
                    println!("  Ed25519 PK:     {} bytes", pk.ed25519_pk_size);
                }
                _ => {
                    println!("{} Unknown key type: {}", "Error:".red(), key_type);
                    println!("Valid types: kem, sign");
                    return Ok(());
                }
            }

            // Show audit entry was created
            println!();
            println!("{} Operation logged to audit chain.", "OK".green());

            if verbose {
                println!("  Audit entries: {}", ctx.audit().count()?);
            }

            Ok(())
        }

        CryptoCommands::Hash { data, algorithm } => {
            let input = data.as_bytes();

            let hash = match algorithm.as_str() {
                "sha256" => ctx.crypto().hash_sha256(input, "cli-hash")?,
                "sha3" | "sha3-256" => ctx.crypto().hash_sha3_256(input, "cli-hash")?,
                "blake3" => ctx.crypto().hash_blake3(input, "cli-hash")?,
                _ => {
                    println!("{} Unknown algorithm: {}", "Error:".red(), algorithm);
                    println!("Valid algorithms: sha256, sha3, blake3");
                    return Ok(());
                }
            };

            println!("{} ({})", hex::encode(hash), algorithm.cyan());

            Ok(())
        }
    }
}
