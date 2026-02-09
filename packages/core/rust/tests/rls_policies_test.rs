//! RLS behavior integration tests
//!
//! These tests require a running PostgreSQL database with migrations applied.
//! Enable with: RUN_RLS_TESTS=1 cargo test --test rls_policies_test -- --nocapture

use chrono::Utc;
use fantasticauth_core::db::users::CreateUserRequest;
use fantasticauth_core::db::{set_connection_context, with_request_context, DbContext, RequestContext};
use fantasticauth_core::models::organization::{
    MembershipStatus, Organization, OrganizationMember, OrganizationRole,
};
use sqlx::PgPool;

async fn setup_db() -> DbContext {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://vault:vault@localhost:5432/vault".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    DbContext::new(pool)
}

fn should_run() -> bool {
    std::env::var("RUN_RLS_TESTS").ok().as_deref() == Some("1")
}

async fn create_tenant(db: &DbContext, tenant_id: &str, slug: &str) {
    let _ = sqlx::query(
        "INSERT INTO tenants (id, slug, name, status, settings, created_at, updated_at) VALUES ($1::uuid, $2, $3, 'active', '{}'::jsonb, NOW(), NOW())"
    )
    .bind(tenant_id)
    .bind(slug)
    .bind(format!("Tenant {}", slug))
    .execute(db.pool())
    .await;
}

async fn insert_webhook_endpoint(db: &DbContext, tenant_id: &str) {
    let mut conn = db.pool().acquire().await.unwrap();
    set_connection_context(&mut conn, tenant_id).await.unwrap();
    let _ = sqlx::query(
        r#"INSERT INTO webhook_endpoints
           (tenant_id, name, url, secret, events, description, headers)
           VALUES ($1::uuid, 'Test', 'https://example.com', 'secret', '["user.created"]'::jsonb, NULL, NULL)"#
    )
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .unwrap();
}

async fn insert_subscription(db: &DbContext, tenant_id: &str) {
    let mut conn = db.pool().acquire().await.unwrap();
    set_connection_context(&mut conn, tenant_id).await.unwrap();
    let _ = sqlx::query(
        r#"INSERT INTO subscriptions (tenant_id, status)
           VALUES ($1::uuid, 'active')"#,
    )
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .unwrap();
}

#[tokio::test]
async fn test_user_rls_self_only() {
    if !should_run() {
        return;
    }

    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4().to_string();
    let slug = format!("rls-{}", &tenant_id[..8]);
    create_tenant(&db, &tenant_id, &slug).await;

    let user1 = db
        .users()
        .create(CreateUserRequest {
            tenant_id: tenant_id.clone(),
            email: format!("user1-{}@example.com", &tenant_id[..8]),
            password_hash: Some("hash1".to_string()),
            email_verified: true,
            profile: None,
            metadata: None,
        })
        .await
        .unwrap();

    let user2 = db
        .users()
        .create(CreateUserRequest {
            tenant_id: tenant_id.clone(),
            email: format!("user2-{}@example.com", &tenant_id[..8]),
            password_hash: Some("hash2".to_string()),
            email_verified: true,
            profile: None,
            metadata: None,
        })
        .await
        .unwrap();

    let member_ctx = RequestContext {
        tenant_id: Some(tenant_id.clone()),
        user_id: Some(user1.id.clone()),
        role: Some("member".to_string()),
    };

    with_request_context(member_ctx, async {
        let other = db.users().find_by_id(&tenant_id, &user2.id).await.unwrap();
        assert!(other.is_none(), "member should not read other users");
    })
    .await;

    let admin_ctx = RequestContext {
        tenant_id: Some(tenant_id.clone()),
        user_id: Some(user1.id.clone()),
        role: Some("admin".to_string()),
    };

    with_request_context(admin_ctx, async {
        let other = db.users().find_by_id(&tenant_id, &user2.id).await.unwrap();
        assert!(other.is_some(), "admin should read other users");
    })
    .await;
}

#[tokio::test]
async fn test_org_rls_membership() {
    if !should_run() {
        return;
    }

    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4().to_string();
    let slug = format!("org-{}", &tenant_id[..8]);
    create_tenant(&db, &tenant_id, &slug).await;

    let user1 = db
        .users()
        .create(CreateUserRequest {
            tenant_id: tenant_id.clone(),
            email: format!("org-user1-{}@example.com", &tenant_id[..8]),
            password_hash: Some("hash1".to_string()),
            email_verified: true,
            profile: None,
            metadata: None,
        })
        .await
        .unwrap();

    let user2 = db
        .users()
        .create(CreateUserRequest {
            tenant_id: tenant_id.clone(),
            email: format!("org-user2-{}@example.com", &tenant_id[..8]),
            password_hash: Some("hash2".to_string()),
            email_verified: true,
            profile: None,
            metadata: None,
        })
        .await
        .unwrap();

    let admin_ctx = RequestContext {
        tenant_id: Some(tenant_id.clone()),
        user_id: Some(user1.id.clone()),
        role: Some("admin".to_string()),
    };

    let org = with_request_context(admin_ctx.clone(), async {
        let now = Utc::now();
        let org = Organization {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            name: "RLS Org".to_string(),
            slug: format!("rls-org-{}", &tenant_id[..8]),
            metadata: serde_json::json!({}),
            sso_required: false,
            sso_config: None,
            created_at: now,
            updated_at: now,
            ..Default::default()
        };

        let created = db.organizations().create(&org).await.unwrap();

        let member = OrganizationMember {
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: created.id.clone(),
            tenant_id: tenant_id.clone(),
            user_id: user1.id.clone(),
            role: OrganizationRole::Member,
            permissions: vec![],
            status: MembershipStatus::Active,
            invited_by: None,
            invited_at: None,
            joined_at: None,
            created_at: now,
            updated_at: now,
        };

        db.organizations()
            .add_member(&tenant_id, &member)
            .await
            .unwrap();
        created
    })
    .await;

    let member_ctx = RequestContext {
        tenant_id: Some(tenant_id.clone()),
        user_id: Some(user1.id.clone()),
        role: Some("member".to_string()),
    };

    with_request_context(member_ctx, async {
        let visible = db
            .organizations()
            .get_by_id(&tenant_id, &org.id)
            .await
            .unwrap();
        assert!(visible.is_some(), "member should read org they belong to");
    })
    .await;

    let other_ctx = RequestContext {
        tenant_id: Some(tenant_id.clone()),
        user_id: Some(user2.id.clone()),
        role: Some("member".to_string()),
    };

    with_request_context(other_ctx, async {
        let visible = db
            .organizations()
            .get_by_id(&tenant_id, &org.id)
            .await
            .unwrap();
        assert!(visible.is_none(), "non-member should not read org");
    })
    .await;
}

#[tokio::test]
async fn test_admin_only_tables() {
    if !should_run() {
        return;
    }

    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4().to_string();
    let slug = format!("admin-{}", &tenant_id[..8]);
    create_tenant(&db, &tenant_id, &slug).await;

    let admin_user = db
        .users()
        .create(CreateUserRequest {
            tenant_id: tenant_id.clone(),
            email: format!("admin-{}@example.com", &tenant_id[..8]),
            password_hash: Some("hash".to_string()),
            email_verified: true,
            profile: None,
            metadata: None,
        })
        .await
        .unwrap();

    let member_user = db
        .users()
        .create(CreateUserRequest {
            tenant_id: tenant_id.clone(),
            email: format!("member-{}@example.com", &tenant_id[..8]),
            password_hash: Some("hash".to_string()),
            email_verified: true,
            profile: None,
            metadata: None,
        })
        .await
        .unwrap();

    let admin_ctx = RequestContext {
        tenant_id: Some(tenant_id.clone()),
        user_id: Some(admin_user.id.clone()),
        role: Some("admin".to_string()),
    };

    let member_ctx = RequestContext {
        tenant_id: Some(tenant_id.clone()),
        user_id: Some(member_user.id.clone()),
        role: Some("member".to_string()),
    };

    with_request_context(admin_ctx.clone(), async {
        insert_webhook_endpoint(&db, &tenant_id).await;
        insert_subscription(&db, &tenant_id).await;
    })
    .await;

    with_request_context(member_ctx.clone(), async {
        let mut conn = db.pool().acquire().await.unwrap();
        set_connection_context(&mut conn, &tenant_id).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_endpoints")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count, 0, "member should not read webhook endpoints");
    })
    .await;

    with_request_context(admin_ctx, async {
        let mut conn = db.pool().acquire().await.unwrap();
        set_connection_context(&mut conn, &tenant_id).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_endpoints")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert!(count >= 1, "admin should read webhook endpoints");

        let billing_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscriptions")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert!(billing_count >= 1, "admin should read subscriptions");
    })
    .await;
}

#[tokio::test]
async fn test_token_tables_self_only() {
    if !should_run() {
        return;
    }

    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4().to_string();
    let slug = format!("token-{}", &tenant_id[..8]);
    create_tenant(&db, &tenant_id, &slug).await;

    let user1 = db
        .users()
        .create(CreateUserRequest {
            tenant_id: tenant_id.clone(),
            email: format!("token-user1-{}@example.com", &tenant_id[..8]),
            password_hash: Some("hash".to_string()),
            email_verified: true,
            profile: None,
            metadata: None,
        })
        .await
        .unwrap();

    let user2 = db
        .users()
        .create(CreateUserRequest {
            tenant_id: tenant_id.clone(),
            email: format!("token-user2-{}@example.com", &tenant_id[..8]),
            password_hash: Some("hash".to_string()),
            email_verified: true,
            profile: None,
            metadata: None,
        })
        .await
        .unwrap();

    let admin_ctx = RequestContext {
        tenant_id: Some(tenant_id.clone()),
        user_id: Some(user1.id.clone()),
        role: Some("admin".to_string()),
    };

    let session = with_request_context(admin_ctx.clone(), async {
        let session_req = fantasticauth_core::db::sessions::CreateSessionRequest {
            tenant_id: tenant_id.clone(),
            user_id: user1.id.clone(),
            access_token_jti: "jti".to_string(),
            refresh_token_hash: "hash".to_string(),
            token_family: "fam".to_string(),
            ip_address: None,
            user_agent: None,
            device_fingerprint: None,
            device_info: serde_json::json!({}),
            location: None,
            mfa_verified: false,
            expires_at: Utc::now() + chrono::Duration::days(1),
            bind_to_ip: false,
            bind_to_device: false,
        };
        db.sessions().create(session_req).await.unwrap()
    })
    .await;

    with_request_context(admin_ctx.clone(), async {
        let mut conn = db.pool().acquire().await.unwrap();
        set_connection_context(&mut conn, &tenant_id).await.unwrap();
        let _ = sqlx::query(
        r#"INSERT INTO refresh_tokens (tenant_id, user_id, session_id, token_hash, token_family, expires_at)
               VALUES ($1::uuid, $2::uuid, $3::uuid, 'tokenhash', 'family', NOW() + INTERVAL '1 day')"#
    )
    .bind(&tenant_id)
    .bind(&user1.id)
    .bind(&session.id)
        .execute(&mut *conn)
        .await
        .unwrap();
    }).await;

    let user2_ctx = RequestContext {
        tenant_id: Some(tenant_id.clone()),
        user_id: Some(user2.id.clone()),
        role: Some("member".to_string()),
    };

    with_request_context(user2_ctx, async {
        let mut conn = db.pool().acquire().await.unwrap();
        set_connection_context(&mut conn, &tenant_id).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count, 0, "other user should not read refresh tokens");
    })
    .await;

    let user1_ctx = RequestContext {
        tenant_id: Some(tenant_id.clone()),
        user_id: Some(user1.id.clone()),
        role: Some("member".to_string()),
    };

    with_request_context(user1_ctx, async {
        let mut conn = db.pool().acquire().await.unwrap();
        set_connection_context(&mut conn, &tenant_id).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count, 1, "owner user should read their refresh tokens");
    })
    .await;
}
