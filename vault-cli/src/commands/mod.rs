//! CLI Commands

pub mod auth;
pub mod config;
pub mod orgs;
pub mod sessions;
pub mod users;

use anyhow::Result;
use comfy_table::{ContentArrangement, Table};
use serde::Serialize;

/// Output format
#[derive(Clone, Copy, Debug, Default)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    Yaml,
}

/// Print data in specified format
pub fn print_data<T: Serialize>(data: &T, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Table => {
            // For single objects, just print pretty JSON for now
            // Complex table formatting would require custom implementation
            let json = serde_json::to_string_pretty(data)?;
            println!("{}", json);
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(data)?;
            println!("{}", json);
        }
        OutputFormat::Yaml => {
            let yaml = serde_yaml::to_string(data)?;
            println!("{}", yaml);
        }
    }
    Ok(())
}

/// Print list as table
pub fn print_table(headers: Vec<&str>, rows: Vec<Vec<String>>) {
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(headers);

    for row in rows {
        table.add_row(row);
    }

    println!("{}", table);
}

/// Confirm dangerous action
pub fn confirm(prompt: &str) -> Result<bool> {
    Ok(dialoguer::Confirm::new()
        .with_prompt(prompt)
        .default(false)
        .interact()?)
}

/// Read password interactively
pub fn read_password(prompt: &str) -> Result<String> {
    Ok(dialoguer::Password::new().with_prompt(prompt).interact()?)
}
