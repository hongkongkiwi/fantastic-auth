//! Metrics collection and Prometheus exposition

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Simple counter metric
#[derive(Clone)]
pub struct Counter {
    value: Arc<RwLock<u64>>,
}

impl Counter {
    pub fn new() -> Self {
        Self {
            value: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn increment(&self) {
        let mut val = self.value.write().await;
        *val += 1;
    }

    pub async fn add(&self, delta: u64) {
        let mut val = self.value.write().await;
        *val += delta;
    }

    pub async fn get(&self) -> u64 {
        *self.value.read().await
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

/// Gauge metric (can go up and down)
#[derive(Clone)]
pub struct Gauge {
    value: Arc<RwLock<f64>>,
}

impl Gauge {
    pub fn new() -> Self {
        Self {
            value: Arc::new(RwLock::new(0.0)),
        }
    }

    pub async fn set(&self, val: f64) {
        let mut v = self.value.write().await;
        *v = val;
    }

    pub async fn increment(&self) {
        let mut v = self.value.write().await;
        *v += 1.0;
    }

    pub async fn decrement(&self) {
        let mut v = self.value.write().await;
        *v -= 1.0;
    }

    pub async fn get(&self) -> f64 {
        *self.value.read().await
    }
}

impl Default for Gauge {
    fn default() -> Self {
        Self::new()
    }
}

/// Histogram for tracking request latencies
#[derive(Clone)]
pub struct Histogram {
    buckets: Vec<f64>,
    counts: Arc<RwLock<Vec<u64>>>,
    sum: Arc<RwLock<f64>>,
    count: Arc<RwLock<u64>>,
}

impl Histogram {
    pub fn new(buckets: Vec<f64>) -> Self {
        let n = buckets.len();
        Self {
            buckets,
            counts: Arc::new(RwLock::new(vec![0; n + 1])),
            sum: Arc::new(RwLock::new(0.0)),
            count: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn observe(&self, value: f64) {
        let mut counts = self.counts.write().await;
        let mut sum = self.sum.write().await;
        let mut count = self.count.write().await;

        *sum += value;
        *count += 1;

        // Find the bucket
        for (i, bucket) in self.buckets.iter().enumerate() {
            if value <= *bucket {
                counts[i] += 1;
                return;
            }
        }
        // If larger than all buckets, increment the +Inf bucket
        counts[self.buckets.len()] += 1;
    }

    pub async fn get_count(&self) -> u64 {
        *self.count.read().await
    }

    pub async fn get_sum(&self) -> f64 {
        *self.sum.read().await
    }
}

/// Prometheus-style metrics registry
#[derive(Clone, Default)]
pub struct MetricsRegistry {
    counters: Arc<RwLock<HashMap<String, Counter>>>,
    gauges: Arc<RwLock<HashMap<String, Gauge>>>,
    histograms: Arc<RwLock<HashMap<String, Histogram>>>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn counter(&self, name: &str) -> Counter {
        let mut counters = self.counters.write().await;
        counters.entry(name.to_string()).or_default().clone()
    }

    pub async fn gauge(&self, name: &str) -> Gauge {
        let mut gauges = self.gauges.write().await;
        gauges.entry(name.to_string()).or_default().clone()
    }

    pub async fn histogram(&self, name: &str, buckets: Vec<f64>) -> Histogram {
        let mut histograms = self.histograms.write().await;
        histograms
            .entry(name.to_string())
            .or_insert_with(|| Histogram::new(buckets))
            .clone()
    }

    /// Export metrics in Prometheus exposition format
    pub async fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Counters
        let counters = self.counters.read().await;
        for (name, counter) in counters.iter() {
            let value = counter.get().await;
            output.push_str(&format!("# TYPE {} counter\n", name));
            output.push_str(&format!("{} {}\n\n", name, value));
        }

        // Gauges
        let gauges = self.gauges.read().await;
        for (name, gauge) in gauges.iter() {
            let value = gauge.get().await;
            output.push_str(&format!("# TYPE {} gauge\n", name));
            output.push_str(&format!("{} {}\n\n", name, value));
        }

        // Histograms
        let histograms = self.histograms.read().await;
        for (name, hist) in histograms.iter() {
            let counts = hist.counts.read().await;
            let sum = hist.get_sum().await;
            let count = hist.get_count().await;

            output.push_str(&format!("# TYPE {} histogram\n", name));

            // Bucket counts
            for (i, bucket) in hist.buckets.iter().enumerate() {
                output.push_str(&format!(
                    "{}_bucket{{le=\"{}\"}} {}\n",
                    name, bucket, counts[i]
                ));
            }
            // +Inf bucket
            output.push_str(&format!(
                "{}_bucket{{le=\"+Inf\"}} {}\n",
                name,
                counts[hist.buckets.len()]
            ));

            output.push_str(&format!("{}_sum {}\n", name, sum));
            output.push_str(&format!("{}_count {}\n\n", name, count));
        }

        output
    }
}
