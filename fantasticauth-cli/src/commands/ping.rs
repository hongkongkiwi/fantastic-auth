//! Ping command for testing connection to Vault

use anyhow::{Context, Result};

/// Test connection to Vault API
pub async fn ping(api_url: &str) -> Result<()> {
    use std::time::Instant;

    println!("🏓 Pinging {}...", api_url);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to create HTTP client")?;

    let start = Instant::now();

    // Try to reach the health endpoint
    let health_url = format!("{}/health", api_url.trim_end_matches('/'));
    let response = client.get(&health_url).send().await;

    let elapsed = start.elapsed();

    match response {
        Ok(resp) => {
            let status = resp.status();
            
            if status.is_success() {
                println!("✅ Vault is reachable!");
                println!("   Response time: {:.2}ms", elapsed.as_secs_f64() * 1000.0);
                println!("   Status: {}", status);

                // Try to parse health response
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(version) = body["version"].as_str() {
                        println!("   Version: {}", version);
                    }
                    if let Some(status) = body["status"].as_str() {
                        println!("   Health: {}", status);
                    }
                }
            } else {
                println!("⚠️  Vault returned error status");
                println!("   Status: {}", status);
            }
        }
        Err(e) => {
            println!("❌ Failed to connect to Vault");
            
            if e.is_timeout() {
                println!("   Error: Connection timed out");
            } else if e.is_connect() {
                println!("   Error: Could not establish connection");
                println!("   Make sure the API URL is correct and the server is running");
            } else {
                println!("   Error: {}", e);
            }
            
            std::process::exit(1);
        }
    }

    Ok(())
}
