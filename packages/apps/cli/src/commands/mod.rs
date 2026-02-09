//! CLI Commands

pub mod auth;
pub mod config;
pub mod migrate;
pub mod orgs;
pub mod ping;
pub mod plugin;
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

/// Print table with numeric alignment for better readability
pub fn print_table_with_numbers(headers: Vec<&str>, rows: Vec<Vec<String>>) {
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

/// Read input interactively with optional default
pub fn read_input(prompt: &str, default: Option<&str>) -> Result<String> {
    let mut input = dialoguer::Input::new().with_prompt(prompt);
    
    if let Some(def) = default {
        input = input.default(def.to_string());
    }
    
    Ok(input.interact_text()?)
}

/// Select from a list of options
pub fn select_option(prompt: &str, options: &[String]) -> Result<usize> {
    Ok(dialoguer::Select::new()
        .with_prompt(prompt)
        .items(options)
        .interact()?)
}

/// Format a timestamp for display
pub fn format_timestamp(ts: &str) -> String {
    // Try to parse and format the timestamp
    ts.chars().take(19).collect::<String>().replace('T', " ")
}

/// Truncate a string to a maximum length with ellipsis
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Display a success message
pub fn success(msg: &str) {
    println!("✅ {}", msg);
}

/// Display an info message
pub fn info(msg: &str) {
    println!("ℹ️  {}", msg);
}

/// Display a warning message
pub fn warning(msg: &str) {
    eprintln!("⚠️  {}", msg);
}

/// Display an error message
pub fn error(msg: &str) {
    eprintln!("❌ {}", msg);
}
