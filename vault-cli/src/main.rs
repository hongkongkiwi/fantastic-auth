//! Vault CLI - Command line interface for Vault
//!
//! Interact with Vault API from the command line.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing::info;

mod client;
mod commands;
mod config;
mod errors;

use commands::OutputFormat;
use config::Config;

/// Vault CLI - User Management API Client
#[derive(Parser)]
#[command(name = "vault")]
#[command(about = "Vault CLI - User Management and Administration")]
#[command(version = vault_core::VERSION)]
struct Cli {
    /// Vault API URL
    #[arg(short = 'u', long, env = "VAULT_API_URL")]
    api_url: Option<String>,

    /// API key for authentication
    #[arg(short = 'k', long, env = "VAULT_API_KEY")]
    api_key: Option<String>,

    /// Tenant ID
    #[arg(short, long, env = "VAULT_TENANT_ID")]
    tenant_id: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: Format,

    /// Quiet mode (suppress non-essential output)
    #[arg(short, long)]
    quiet: bool,

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
    /// Authentication commands
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },

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

    /// Plugin management commands
    Plugins {
        #[command(subcommand)]
        command: PluginCommands,
    },

    /// Migration tools
    Migrate {
        #[command(subcommand)]
        command: MigrateCommands,
    },

    /// Configuration commands
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Test connection to Vault
    Ping,
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Login to Vault
    Login {
        /// Email address (optional if using API key)
        email: Option<String>,
        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
        /// API key for service account authentication
        #[arg(short = 'k', long)]
        api_key: Option<String>,
    },

    /// Logout from Vault
    Logout,

    /// Show current user info
    Whoami,
}

#[derive(Subcommand)]
enum UserCommands {
    /// List users
    List {
        /// Filter by email
        #[arg(short, long)]
        email: Option<String>,
        /// Filter by status
        #[arg(short, long)]
        status: Option<String>,
        /// Page number
        #[arg(short, long, default_value = "1")]
        page: i64,
        /// Number of results per page
        #[arg(short, long, default_value = "20")]
        per_page: i64,
    },
    /// Get user details
    Get { id: String },
    /// Create new user
    Create {
        /// Email address
        #[arg(short, long)]
        email: String,
        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
        /// Display name
        #[arg(short, long)]
        name: Option<String>,
        /// Mark email as verified
        #[arg(long)]
        email_verified: bool,
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
        /// New status
        #[arg(short, long)]
        status: Option<String>,
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
    List {
        /// Page number
        #[arg(short, long, default_value = "1")]
        page: i64,
        /// Number of results per page
        #[arg(short, long, default_value = "20")]
        per_page: i64,
        /// Filter by status
        #[arg(short, long)]
        status: Option<String>,
    },
    /// Get organization details
    Get { id: String },
    /// Create organization
    Create {
        /// Organization name
        #[arg(short, long)]
        name: String,
        /// Organization slug (optional, auto-generated from name)
        #[arg(short, long)]
        slug: Option<String>,
        /// Description
        #[arg(short, long)]
        description: Option<String>,
    },
    /// Update organization
    Update {
        id: String,
        /// New name
        #[arg(short, long)]
        name: Option<String>,
        /// New description
        #[arg(long)]
        description: Option<String>,
        /// Website URL
        #[arg(short, long)]
        website: Option<String>,
    },
    /// Delete organization
    Delete {
        id: String,
        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },
    /// List organization members
    Members {
        #[command(subcommand)]
        command: OrgMemberCommands,
    },
}

#[derive(Subcommand)]
enum OrgMemberCommands {
    /// List members
    List { org_id: String },
    /// Add member to organization
    Add {
        org_id: String,
        /// User ID to add
        #[arg(short, long)]
        user_id: String,
        /// Role (admin, member, viewer)
        #[arg(short, long, default_value = "member")]
        role: String,
    },
    /// Remove member from organization
    Remove {
        org_id: String,
        /// User ID to remove
        #[arg(short, long)]
        user_id: String,
    },
    /// Update member role
    Update {
        org_id: String,
        /// User ID
        #[arg(short, long)]
        user_id: String,
        /// New role (admin, member, viewer)
        #[arg(short, long)]
        role: String,
    },
}

#[derive(Subcommand)]
enum SessionCommands {
    /// List active sessions
    List {
        /// Filter by user ID (admin only)
        #[arg(short, long)]
        user_id: Option<String>,
    },
    /// Revoke a session
    Revoke {
        session_id: String,
        /// User ID (admin only, for revoking other user sessions)
        #[arg(short, long)]
        user_id: Option<String>,
    },
    /// Revoke all sessions for a user
    RevokeAll {
        /// User ID (if not provided, revokes own sessions)
        #[arg(short, long)]
        user_id: Option<String>,
        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
#[clap(rename_all = "kebab-case")]
enum PluginCommands {
    /// List all installed plugins
    List {
        /// Show detailed information
        #[arg(short, long)]
        detailed: bool,
    },
    /// Install a plugin
    Install {
        /// Path to plugin file or directory
        path: PathBuf,
        /// Plugin name (optional)
        #[arg(short, long)]
        name: Option<String>,
        /// Enable plugin immediately
        #[arg(short, long)]
        enable: bool,
    },
    /// Uninstall a plugin
    Uninstall {
        /// Plugin name
        name: String,
        /// Force uninstall even if enabled
        #[arg(short, long)]
        force: bool,
    },
    /// Enable a plugin
    Enable {
        /// Plugin name
        name: String,
    },
    /// Disable a plugin
    Disable {
        /// Plugin name
        name: String,
    },
    /// Show plugin details
    Show {
        /// Plugin name
        name: String,
    },
    /// Check plugin health
    Health {
        /// Plugin name (if not provided, checks all)
        name: Option<String>,
    },
    /// Create a new plugin scaffold
    Create {
        /// Plugin name
        name: String,
        /// Plugin type
        #[arg(short, long, default_value = "builtin")]
        plugin_type: PluginTypeArg,
        /// Output directory
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PluginTypeArg {
    Native,
    Wasm,
    Builtin,
}

#[derive(Subcommand)]
#[clap(rename_all = "kebab-case")]
enum MigrateCommands {
    /// Import users from CSV or JSON
    ImportUsers {
        /// Path to import file
        file: PathBuf,
        /// File format (auto-detected if not specified)
        #[arg(short, long)]
        format: Option<ImportFormat>,
        /// Dry run (validate without importing)
        #[arg(long)]
        dry_run: bool,
    },
    /// Export users to file
    ExportUsers {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Export format
        #[arg(short, long, default_value = "json")]
        format: ExportFormat,
        /// Filter by status
        #[arg(short, long)]
        status: Option<String>,
    },
    /// Import users from Auth0
    FromAuth0 {
        /// Auth0 domain
        #[arg(short, long)]
        domain: String,
        /// Auth0 management API token
        #[arg(short, long)]
        token: String,
        /// Connection ID (optional)
        #[arg(short, long)]
        connection: Option<String>,
    },
    /// Import users from Firebase
    FromFirebase {
        /// Path to Firebase credentials JSON
        #[arg(short, long)]
        credentials: PathBuf,
        /// Dry run (validate without importing)
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ImportFormat {
    Csv,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ExportFormat {
    Csv,
    Json,
    Yaml,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show,
    /// Set configuration value
    Set {
        key: String,
        value: String,
    },
    /// Set API URL
    #[command(name = "set-url")]
    SetUrl {
        url: String,
    },
    /// Set API key
    #[command(name = "set-api-key")]
    SetApiKey {
        key: String,
    },
    /// Set default tenant
    #[command(name = "set-tenant")]
    SetTenant {
        tenant_id: String,
    },
    /// Initialize configuration interactively
    Init,
    /// Reset configuration to defaults
    Reset {
        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt::init();
    }

    if !cli.quiet {
        info!("Vault CLI v{}", vault_core::VERSION);
    }

    // Load configuration
    let config = Config::load()?;

    // Determine effective values (CLI args override config)
    let api_url = cli.api_url.or(config.api_url.clone()).unwrap_or_else(|| {
        eprintln!("Error: API URL not configured. Use --api-url or run 'vault config init'");
        std::process::exit(1);
    });

    let format: OutputFormat = cli.format.into();
    let tenant_id = cli.tenant_id.or(config.tenant_id.clone()).unwrap_or_default();

    match cli.command {
        Commands::Auth { command } => match command {
            AuthCommands::Login {
                email,
                password,
                api_key,
            } => {
                if let Some(key) = api_key {
                    commands::auth::login_with_api_key(&api_url, &key, &tenant_id).await?;
                } else if let Some(email) = email {
                    commands::auth::login(&api_url, &email, password.as_deref()).await?;
                } else {
                    anyhow::bail!("Either email or --api-key must be provided");
                }
            }
            AuthCommands::Logout => {
                commands::auth::logout()?;
            }
            AuthCommands::Whoami => {
                let token = config.token.as_deref().context("Not logged in")?;
                commands::auth::whoami(&api_url, token, format).await?;
            }
        },

        Commands::Users { command } => {
            let token = config.token.as_deref().context("Not logged in")?;

            match command {
                UserCommands::List {
                    email,
                    status,
                    page,
                    per_page,
                } => {
                    commands::users::list(
                        &api_url,
                        token,
                        &tenant_id,
                        email.as_deref(),
                        status.as_deref(),
                        page,
                        per_page,
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
                    email_verified,
                } => {
                    commands::users::create(
                        &api_url,
                        token,
                        &tenant_id,
                        &email,
                        password.as_deref(),
                        name.as_deref(),
                        email_verified,
                    )
                    .await?;
                }
                UserCommands::Update { id, email, name, status } => {
                    commands::users::update(
                        &api_url,
                        token,
                        &tenant_id,
                        &id,
                        email.as_deref(),
                        name.as_deref(),
                        status.as_deref(),
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

            match command {
                OrgCommands::List {
                    page,
                    per_page,
                    status,
                } => {
                    commands::orgs::list(&api_url, token, &tenant_id, page, per_page, status.as_deref(), format).await?;
                }
                OrgCommands::Get { id } => {
                    commands::orgs::get(&api_url, token, &tenant_id, &id, format).await?;
                }
                OrgCommands::Create {
                    name,
                    slug,
                    description,
                } => {
                    commands::orgs::create(&api_url, token, &tenant_id, &name, slug.as_deref(), description.as_deref())
                        .await?;
                }
                OrgCommands::Update {
                    id,
                    name,
                    description,
                    website,
                } => {
                    commands::orgs::update(
                        &api_url,
                        token,
                        &tenant_id,
                        &id,
                        name.as_deref(),
                        description.as_deref(),
                        website.as_deref(),
                    )
                    .await?;
                }
                OrgCommands::Delete { id, force } => {
                    commands::orgs::delete(&api_url, token, &tenant_id, &id, force).await?;
                }
                OrgCommands::Members { command } => match command {
                    OrgMemberCommands::List { org_id } => {
                        commands::orgs::members(&api_url, token, &tenant_id, &org_id, format).await?;
                    }
                    OrgMemberCommands::Add { org_id, user_id, role } => {
                        commands::orgs::add_member(&api_url, token, &tenant_id, &org_id, &user_id, &role)
                            .await?;
                    }
                    OrgMemberCommands::Remove { org_id, user_id } => {
                        commands::orgs::remove_member(&api_url, token, &tenant_id, &org_id, &user_id)
                            .await?;
                    }
                    OrgMemberCommands::Update { org_id, user_id, role } => {
                        commands::orgs::update_member(&api_url, token, &tenant_id, &org_id, &user_id, &role)
                            .await?;
                    }
                },
            }
        }

        Commands::Sessions { command } => {
            let token = config.token.as_deref().context("Not logged in")?;

            match command {
                SessionCommands::List { user_id } => {
                    if let Some(uid) = user_id {
                        commands::sessions::list_user_sessions(&api_url, token, &tenant_id, &uid, format).await?;
                    } else {
                        commands::sessions::list(&api_url, token, &tenant_id, format).await?;
                    }
                }
                SessionCommands::Revoke { session_id, user_id } => {
                    if let Some(uid) = user_id {
                        commands::sessions::revoke_user_session(&api_url, token, &tenant_id, &uid, &session_id)
                            .await?;
                    } else {
                        commands::sessions::revoke(&api_url, token, &tenant_id, &session_id).await?;
                    }
                }
                SessionCommands::RevokeAll { user_id, force } => {
                    if let Some(uid) = user_id {
                        commands::sessions::revoke_all_user_sessions(&api_url, token, &tenant_id, &uid, force)
                            .await?;
                    } else {
                        commands::sessions::revoke_all(&api_url, token, &tenant_id, force).await?;
                    }
                }
            }
        }

        Commands::Plugins { command } => {
            let token = config.token.as_deref().context("Not logged in")?;

            match command {
                PluginCommands::List { detailed } => {
                    println!("Listing plugins... (detailed: {})", detailed);
                    println!("\nExample plugins that would be listed:");
                    println!("  example-plugin   v1.0.0  builtin   ✓ enabled  ● healthy");
                    println!("  ldap-plugin      v1.0.0  builtin   ✓ enabled  ● healthy");
                    println!("  webhook-plugin   v1.0.0  builtin   ✓ enabled  ● healthy");
                }
                PluginCommands::Install { path, name, enable } => {
                    println!("Installing plugin from: {:?}", path);
                    if let Some(n) = name {
                        println!("Plugin name: {}", n);
                    }
                    println!("Enable immediately: {}", enable);
                }
                PluginCommands::Uninstall { name, force } => {
                    println!("Uninstalling plugin: {}", name);
                    println!("Force: {}", force);
                }
                PluginCommands::Enable { name } => {
                    println!("Enabling plugin: {}", name);
                }
                PluginCommands::Disable { name } => {
                    println!("Disabling plugin: {}", name);
                }
                PluginCommands::Show { name } => {
                    println!("Showing plugin details: {}", name);
                }
                PluginCommands::Health { name } => {
                    if let Some(n) = name {
                        println!("Checking health of plugin: {}", n);
                    } else {
                        println!("Checking health of all plugins");
                    }
                }
                PluginCommands::Create { name, plugin_type, output } => {
                    let output_dir = output.unwrap_or_else(|| PathBuf::from("./plugins"));
                    let cli_plugin_type = match plugin_type {
                        PluginTypeArg::Native => commands::plugin::PluginTypeArg::Native,
                        PluginTypeArg::Wasm => commands::plugin::PluginTypeArg::Wasm,
                        PluginTypeArg::Builtin => commands::plugin::PluginTypeArg::Builtin,
                    };

                    let author = std::env::var("USER").unwrap_or_else(|_| "Unknown".to_string());
                    let description = format!("A custom {} plugin for Vault", match plugin_type {
                        PluginTypeArg::Native => "native",
                        PluginTypeArg::Wasm => "wasm",
                        PluginTypeArg::Builtin => "builtin",
                    });

                    match commands::plugin::PluginScaffold::create(
                        &name,
                        cli_plugin_type,
                        &output_dir,
                        &description,
                        &author,
                    ) {
                        Ok(_) => println!("\n✅ Plugin scaffold created successfully!"),
                        Err(e) => eprintln!("Error creating plugin scaffold: {}", e),
                    }
                }
            }
        }

        Commands::Migrate { command } => {
            let token = config.token.as_deref().context("Not logged in")?;

            match command {
                MigrateCommands::ImportUsers { file, format, dry_run } => {
                    commands::migrate::import_users(
                        &api_url,
                        token,
                        &tenant_id,
                        &file,
                        format.map(|f| match f {
                            ImportFormat::Csv => commands::migrate::ImportFormat::Csv,
                            ImportFormat::Json => commands::migrate::ImportFormat::Json,
                        }),
                        dry_run,
                    )
                    .await?;
                }
                MigrateCommands::ExportUsers { output, format, status } => {
                    commands::migrate::export_users(
                        &api_url,
                        token,
                        &tenant_id,
                        output.as_ref(),
                        match format {
                            ExportFormat::Csv => commands::migrate::ExportFormat::Csv,
                            ExportFormat::Json => commands::migrate::ExportFormat::Json,
                            ExportFormat::Yaml => commands::migrate::ExportFormat::Yaml,
                        },
                        status.as_deref(),
                    )
                    .await?;
                }
                MigrateCommands::FromAuth0 { domain, token: auth0_token, connection } => {
                    commands::migrate::import_from_auth0(
                        &api_url,
                        token,
                        &tenant_id,
                        &domain,
                        &auth0_token,
                        connection.as_deref(),
                    )
                    .await?;
                }
                MigrateCommands::FromFirebase { credentials, dry_run } => {
                    commands::migrate::import_from_firebase(
                        &api_url,
                        token,
                        &tenant_id,
                        &credentials,
                        dry_run,
                    )
                    .await?;
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
            ConfigCommands::SetUrl { url } => {
                commands::config::set("api_url", &url)?;
            }
            ConfigCommands::SetApiKey { key } => {
                commands::config::set("token", &key)?;
            }
            ConfigCommands::SetTenant { tenant_id } => {
                commands::config::set("tenant_id", &tenant_id)?;
            }
            ConfigCommands::Init => {
                commands::config::init().await?;
            }
            ConfigCommands::Reset { force } => {
                commands::config::reset(force)?;
            }
        },

        Commands::Ping => {
            commands::ping::ping(&api_url).await?;
        }
    }

    Ok(())
}
