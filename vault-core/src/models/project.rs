//! Project and Application models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub tenant_id: String,
    pub organization_id: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub status: ProjectStatus,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "project_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ProjectStatus {
    #[default]
    Active,
    Inactive,
    Archived,
}

impl FromStr for ProjectStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(ProjectStatus::Active),
            "inactive" => Ok(ProjectStatus::Inactive),
            "archived" => Ok(ProjectStatus::Archived),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Application {
    pub id: String,
    pub tenant_id: String,
    pub organization_id: String,
    pub project_id: String,
    pub name: String,
    pub app_type: ApplicationType,
    pub status: ApplicationStatus,
    pub settings: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "application_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ApplicationType {
    #[default]
    Oidc,
    Saml,
    Api,
}

impl FromStr for ApplicationType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "oidc" => Ok(ApplicationType::Oidc),
            "saml" => Ok(ApplicationType::Saml),
            "api" => Ok(ApplicationType::Api),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "application_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ApplicationStatus {
    #[default]
    Active,
    Inactive,
}

impl FromStr for ApplicationStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(ApplicationStatus::Active),
            "inactive" => Ok(ApplicationStatus::Inactive),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectRole {
    pub id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub is_system_role: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectRoleAssignment {
    pub id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub role_id: String,
    pub user_id: String,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectGrant {
    pub id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub granted_organization_id: String,
    pub default_role_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Project {
    pub fn new(
        tenant_id: impl Into<String>,
        organization_id: impl Into<String>,
        name: impl Into<String>,
        slug: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Project {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.into(),
            organization_id: organization_id.into(),
            name: name.into(),
            slug: slug.into(),
            description: None,
            status: ProjectStatus::Active,
            metadata: serde_json::json!({}),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }
}

impl Application {
    pub fn new(
        tenant_id: impl Into<String>,
        organization_id: impl Into<String>,
        project_id: impl Into<String>,
        name: impl Into<String>,
        app_type: ApplicationType,
    ) -> Self {
        let now = Utc::now();
        Application {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.into(),
            organization_id: organization_id.into(),
            project_id: project_id.into(),
            name: name.into(),
            app_type,
            status: ApplicationStatus::Active,
            settings: serde_json::json!({}),
            created_at: now,
            updated_at: now,
        }
    }
}
