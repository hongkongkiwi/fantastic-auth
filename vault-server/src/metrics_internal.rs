use std::sync::atomic::{AtomicU64, Ordering};

static AUDIT_ROTATIONS: AtomicU64 = AtomicU64::new(0);
static AUDIT_ROTATION_ERRORS: AtomicU64 = AtomicU64::new(0);
static AUDIT_PRUNES: AtomicU64 = AtomicU64::new(0);
static AUDIT_PRUNE_ERRORS: AtomicU64 = AtomicU64::new(0);

pub fn record_audit_rotation() {
    AUDIT_ROTATIONS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_audit_rotation_error() {
    AUDIT_ROTATION_ERRORS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_audit_prune() {
    AUDIT_PRUNES.fetch_add(1, Ordering::Relaxed);
}

pub fn record_audit_prune_error() {
    AUDIT_PRUNE_ERRORS.fetch_add(1, Ordering::Relaxed);
}

pub fn audit_rotation_count() -> u64 {
    AUDIT_ROTATIONS.load(Ordering::Relaxed)
}

pub fn audit_rotation_error_count() -> u64 {
    AUDIT_ROTATION_ERRORS.load(Ordering::Relaxed)
}

pub fn audit_prune_count() -> u64 {
    AUDIT_PRUNES.load(Ordering::Relaxed)
}

pub fn audit_prune_error_count() -> u64 {
    AUDIT_PRUNE_ERRORS.load(Ordering::Relaxed)
}
