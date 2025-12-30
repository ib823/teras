//! Digital signature commands.

use clap::{Args, Subcommand};
use colored::Colorize;
use std::sync::Arc;
use teras_core::error::TerasResult;
use teras_jejak::{storage::MemoryStorage, AuditLog};
use teras_sandi::{ExportFormat, SignatureMetadata, SigningService};

/// Sandi (signing) command arguments.
#[derive(Args)]
pub struct SandiArgs {
    #[command(subcommand)]
    pub command: SandiCommands,
}

#[derive(Subcommand)]
pub enum SandiCommands {
    /// Generate a new signing keypair
    Keygen {
        /// Key identifier
        #[arg(short, long)]
        id: String,
    },

    /// Sign a document
    Sign {
        /// Key ID to use for signing
        #[arg(short, long)]
        key_id: String,

        /// Data to sign (or path to file with @prefix)
        data: String,

        /// Output file for signature (if not specified, prints to stdout)
        #[arg(short, long)]
        output: Option<String>,

        /// Signer name for metadata
        #[arg(long)]
        signer: Option<String>,

        /// Signing reason for metadata
        #[arg(long)]
        reason: Option<String>,
    },

    /// Verify a signature
    Verify {
        /// Signature file or data
        signature: String,

        /// Original document data (or path with @prefix)
        data: String,

        /// Key ID to verify against
        #[arg(short, long)]
        key_id: String,
    },

    /// List signing keys
    List,
}

/// Execute sandi command.
#[allow(clippy::too_many_lines)]
pub async fn execute(args: SandiArgs, verbose: bool) -> TerasResult<()> {
    // Create a signing service with in-memory storage and timestamp authority
    let storage = MemoryStorage::new();
    let audit_log = Arc::new(std::sync::RwLock::new(AuditLog::new(Box::new(storage))));
    let mut service = SigningService::with_timestamp_authority(audit_log.clone(), "teras-cli-tsa");

    match args.command {
        SandiCommands::Keygen { id } => {
            println!(
                "Generating hybrid signing keypair with ID: {}...",
                id.cyan()
            );
            println!();

            let info = service.generate_key(&id)?;

            println!("{}", "Hybrid Signing Keypair Generated".green().bold());
            println!("  Key ID:         {}", info.key_id);
            println!("  Algorithm:      {}", info.algorithm);
            println!("  Dilithium PK:   {} bytes", info.dilithium_pk_size);
            println!("  Ed25519 PK:     {} bytes", info.ed25519_pk_size);
            println!(
                "  Created:        {}",
                info.created_at.format("%Y-%m-%d %H:%M:%S UTC")
            );

            println!();
            println!("{} Key generated and stored in session.", "OK".green());
            println!(
                "{}",
                "Note: Keys are session-only (not persisted to disk).".yellow()
            );

            if verbose {
                let log = audit_log.read().unwrap();
                println!("  Audit entries: {}", log.count()?);
            }

            Ok(())
        }

        SandiCommands::Sign {
            key_id,
            data,
            output,
            signer,
            reason,
        } => {
            // First generate a key (since we're using session-only storage)
            println!(
                "{}",
                "Note: Generating session key for signing demo...".yellow()
            );
            service.generate_key(&key_id)?;

            // Parse data (check for @file prefix)
            let document = if let Some(path) = data.strip_prefix('@') {
                std::fs::read(path).map_err(teras_core::error::TerasError::IoError)?
            } else {
                data.into_bytes()
            };

            // Build metadata if provided
            let metadata = if signer.is_some() || reason.is_some() {
                let mut meta = SignatureMetadata::new();
                if let Some(s) = signer {
                    meta = meta.with_signer(s);
                }
                if let Some(r) = reason {
                    meta = meta.with_reason(r);
                }
                Some(meta)
            } else {
                None
            };

            println!(
                "Signing {} bytes with key {}...",
                document.len(),
                key_id.cyan()
            );

            let signed = service.sign_with_options(&key_id, document, None, None, metadata)?;

            // Export to portable format
            let json = teras_sandi::export_signature(&signed, ExportFormat::JsonPretty)?;

            if let Some(output_path) = output {
                std::fs::write(&output_path, &json)?;
                println!();
                println!("{}", "Document Signed Successfully".green().bold());
                println!("  Document ID:  {}", signed.id);
                println!("  Algorithm:    {}", signed.algorithm);
                println!(
                    "  Signed at:    {}",
                    signed.signed_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
                if signed.timestamp_token.is_some() {
                    println!("  Timestamped:  Yes");
                }
                println!("  Output:       {}", output_path.cyan());
            } else {
                println!();
                println!("{}", "Signature (JSON):".green().bold());
                println!("{json}");
            }

            println!();
            println!("{} Signature created with audit logging.", "OK".green());

            Ok(())
        }

        SandiCommands::Verify {
            signature,
            data,
            key_id,
        } => {
            // Generate the same key for verification demo
            println!(
                "{}",
                "Note: Generating session key for verification demo...".yellow()
            );
            service.generate_key(&key_id)?;

            // Parse signature JSON
            let sig_json = if let Some(path) = signature.strip_prefix('@') {
                std::fs::read_to_string(path)?
            } else {
                signature
            };

            // Import signature
            let signed = service.import(&sig_json)?;

            // Parse document data (for hash comparison)
            let _document = if let Some(path) = data.strip_prefix('@') {
                std::fs::read(path)?
            } else {
                data.into_bytes()
            };

            println!(
                "Verifying signature for document ID: {}...",
                signed.id.to_string().cyan()
            );

            // For demo purposes, we show the verification flow
            // In a real scenario, we'd verify against a stored/imported public key
            println!();
            println!("{}", "Signature Details:".green().bold());
            println!("  Document ID:  {}", signed.id);
            println!("  Key ID:       {}", signed.key_id);
            println!("  Algorithm:    {}", signed.algorithm);
            println!(
                "  Signed at:    {}",
                signed.signed_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!(
                "  Document hash: {}...",
                hex::encode(&signed.document_hash[..8])
            );

            if signed.timestamp_token.is_some() {
                let ts = signed.timestamp_token.as_ref().unwrap();
                println!();
                println!("{}", "Timestamp Token:".cyan());
                println!("  TSA:          {}", ts.tsa_id);
                println!(
                    "  Timestamp:    {}",
                    ts.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
                );
                println!("  Serial:       {}", &ts.serial[..8]);
            }

            println!();
            println!(
                "{}",
                "Note: Full verification requires the original signing key.".yellow()
            );
            println!("In a production environment, public keys would be stored and verified.");

            Ok(())
        }

        SandiCommands::List => {
            let keys = service.list_keys()?;

            println!("{}", "Signing Keys".green().bold());
            println!();

            if keys.is_empty() {
                println!("{}", "No signing keys in session.".yellow());
                println!("Use 'teras sandi keygen' to generate a key.");
            } else {
                for key_id in keys {
                    if let Some(info) = service.get_key_info(&key_id) {
                        println!("  {} {}", "*".cyan(), key_id);
                        println!("    Algorithm: {}", info.algorithm);
                        println!(
                            "    Created:   {}",
                            info.created_at.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                    }
                }
            }

            Ok(())
        }
    }
}
