//! Vault CLI - Command line interface for Vault
//!
//! Interact with Vault API from the command line.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tracing::info;

mod client;
mod commands;
mod config;

use commands::OutputFormat;
use config::Config;

/// Vault CLI - User Management API Client
#[derive(Parser)]
#[command(name = "vault")]
#[command(about = "Vault CLI - User Management API")]
#[command(version = vault_core::VERSION)]
struct Cli {
    /// Vault API URL
    #[arg(short, long, env = "VAULT_API_URL")]
    api_url: Option<String>,

    /// API key for authentication
    #[arg(short, long, env = "VAULT_API_KEY")]
    api_key: Option<String>,

    /// Tenant ID
    #[arg(short, long, env = "VAULT_TENANT_ID")]
    tenant_id: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: Format,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    Table,
    Json,
    Yaml,
}

impl From<Format> for OutputFormat {
    fn from(f: Format) -> Self {
        match f {
            Format::Table => OutputFormat::Table,
            Format::Json => OutputFormat::Json,
            Format::Yaml => OutputFormat::Yaml,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Login to Vault
    Login {
        /// Email address
        email: String,
        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Logout from Vault
    Logout,

    /// Show current user info
    Whoami,

    /// User management commands
    Users {
        #[command(subcommand)]
        command: UserCommands,
    },

    /// Organization management commands
    Orgs {
        #[command(subcommand)]
        command: OrgCommands,
    },

    /// Session management commands
    Sessions {
        #[command(subcommand)]
        command: SessionCommands,
    },

    /// Configuration commands
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
}

#[derive(Subcommand)]
enum UserCommands {
    /// List users
    List {
        /// Filter by email
        #[arg(short, long)]
        email: Option<String>,
        /// Number of results per page
        #[arg(short, long, default_value = "20")]
        limit: u32,
    },
    /// Get user details
    Get { id: String },
    /// Create new user
    Create {
        /// Email address
        email: String,
        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
        /// Display name
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Update user
    Update {
        id: String,
        /// New email
        #[arg(short, long)]
        email: Option<String>,
        /// New name
        #[arg(long)]
        name: Option<String>,
    },
    /// Delete user
    Delete {
        id: String,
        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },
    /// Suspend user
    Suspend {
        id: String,
        /// Reason for suspension
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// Activate suspended user
    Activate { id: String },
}

#[derive(Subcommand)]
enum OrgCommands {
    /// List organizations
    List,
    /// Get organization details
    Get { id: String },
    /// Create organization
    Create {
        /// Organization name
        name: String,
        /// Organization slug
        #[arg(short, long)]
        slug: Option<String>,
    },
    /// Delete organization
    Delete {
        id: String,
        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },
    /// List organization members
    Members { org_id: String },
}

#[derive(Subcommand)]
enum SessionCommands {
    /// List active sessions
    List,
    /// Revoke a session
    Revoke { id: String },
    /// Revoke all sessions (logout everywhere)
    RevokeAll {
        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show,
    /// Set configuration value
    Set { key: String, value: String },
    /// Initialize configuration
    Init,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt::init();
    }

    info!("Vault CLI v{}", vault_core::VERSION);

    // Load configuration
    let config = Config::load()?;

    // Determine effective values (CLI args override config)
    let api_url = cli.api_url.or(config.api_url).unwrap_or_else(|| {
        eprintln!("Error: API URL not configured. Use --api-url or run 'vault config init'");
        std::process::exit(1);
    });

    let format: OutputFormat = cli.format.into();

    match cli.command {
        Commands::Login { email, password } => {
            commands::auth::login(&api_url, &email, password.as_deref()).await?;
        }
        Commands::Logout => {
            commands::auth::logout()?;
        }
        Commands::Whoami => {
            let token = config.token.as_deref().context("Not logged in")?;
            commands::auth::whoami(&api_url, token).await?;
        }
        Commands::Users { command } => {
            let token = config.token.as_deref().context("Not logged in")?;
            let tenant_id = cli.tenant_id.or(config.tenant_id).unwrap_or_default();

            match command {
                UserCommands::List { email, limit } => {
                    commands::users::list(
                        &api_url,
                        token,
                        &tenant_id,
                        email.as_deref(),
                        limit,
                        format,
                    )
                    .await?;
                }
                UserCommands::Get { id } => {
                    commands::users::get(&api_url, token, &tenant_id, &id, format).await?;
                }
                UserCommands::Create {
                    email,
                    password,
                    name,
                } => {
                    commands::users::create(
                        &api_url,
                        token,
                        &tenant_id,
                        &email,
                        password.as_deref(),
                        name.as_deref(),
                    )
                    .await?;
                }
                UserCommands::Update { id, email, name } => {
                    commands::users::update(
                        &api_url,
                        token,
                        &tenant_id,
                        &id,
                        email.as_deref(),
                        name.as_deref(),
                    )
                    .await?;
                }
                UserCommands::Delete { id, force } => {
                    commands::users::delete(&api_url, token, &tenant_id, &id, force).await?;
                }
                UserCommands::Suspend { id, reason } => {
                    commands::users::suspend(&api_url, token, &tenant_id, &id, reason.as_deref())
                        .await?;
                }
                UserCommands::Activate { id } => {
                    commands::users::activate(&api_url, token, &tenant_id, &id).await?;
                }
            }
        }
        Commands::Orgs { command } => {
            let token = config.token.as_deref().context("Not logged in")?;
            let tenant_id = cli.tenant_id.or(config.tenant_id).unwrap_or_default();

            match command {
                OrgCommands::List => {
                    commands::orgs::list(&api_url, token, &tenant_id, format).await?;
                }
                OrgCommands::Get { id } => {
                    commands::orgs::get(&api_url, token, &tenant_id, &id, format).await?;
                }
                OrgCommands::Create { name, slug } => {
                    commands::orgs::create(&api_url, token, &tenant_id, &name, slug.as_deref())
                        .await?;
                }
                OrgCommands::Delete { id, force } => {
                    commands::orgs::delete(&api_url, token, &tenant_id, &id, force).await?;
                }
                OrgCommands::Members { org_id } => {
                    commands::orgs::members(&api_url, token, &tenant_id, &org_id, format).await?;
                }
            }
        }
        Commands::Sessions { command } => {
            let token = config.token.as_deref().context("Not logged in")?;
            let tenant_id = cli.tenant_id.or(config.tenant_id).unwrap_or_default();

            match command {
                SessionCommands::List => {
                    commands::sessions::list(&api_url, token, &tenant_id, format).await?;
                }
                SessionCommands::Revoke { id } => {
                    commands::sessions::revoke(&api_url, token, &tenant_id, &id).await?;
                }
                SessionCommands::RevokeAll { force } => {
                    commands::sessions::revoke_all(&api_url, token, &tenant_id, force).await?;
                }
            }
        }
        Commands::Config { command } => match command {
            ConfigCommands::Show => {
                commands::config::show(format)?;
            }
            ConfigCommands::Set { key, value } => {
                commands::config::set(&key, &value)?;
            }
            ConfigCommands::Init => {
                commands::config::init().await?;
            }
        },
    }

    Ok(())
}
