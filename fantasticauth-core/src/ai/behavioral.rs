//! Behavioral Biometrics System
//!
//! This module provides behavioral biometric analysis for user authentication:
//! - Keystroke dynamics (typing cadence, rhythm)
//! - Mouse movement patterns
//! - Touch gesture dynamics
//! - Behavioral pattern matching and scoring

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::error::{AiError, AiResult};
use super::ml_models::ModelManager;
use crate::db::DbContext;

/// Behavioral data captured during authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralData {
    /// Keystroke dynamics
    pub keystroke: Option<KeystrokeDynamics>,
    /// Mouse movement patterns
    pub mouse: Option<MouseDynamics>,
    /// Touch gesture dynamics
    pub touch: Option<TouchDynamics>,
    /// Time spent on page (milliseconds)
    pub time_on_page_ms: u64,
    /// Number of form interactions
    pub form_interactions: u32,
    /// Scrolling behavior
    pub scroll_events: Vec<ScrollEvent>,
    /// Focus/blur events
    pub focus_events: Vec<FocusEvent>,
    /// Timestamp
    pub captured_at: DateTime<Utc>,
}

impl BehavioralData {
    /// Create new behavioral data
    pub fn new() -> Self {
        Self {
            keystroke: None,
            mouse: None,
            touch: None,
            time_on_page_ms: 0,
            form_interactions: 0,
            scroll_events: Vec::new(),
            focus_events: Vec::new(),
            captured_at: Utc::now(),
        }
    }

    /// Add keystroke data
    pub fn with_keystroke(mut self, keystroke: KeystrokeDynamics) -> Self {
        self.keystroke = Some(keystroke);
        self
    }

    /// Add mouse data
    pub fn with_mouse(mut self, mouse: MouseDynamics) -> Self {
        self.mouse = Some(mouse);
        self
    }

    /// Add touch data
    pub fn with_touch(mut self, touch: TouchDynamics) -> Self {
        self.touch = Some(touch);
        self
    }

    /// Check if any biometric data is present
    pub fn has_biometrics(&self) -> bool {
        self.keystroke.is_some() || self.mouse.is_some() || self.touch.is_some()
    }

    /// Calculate overall entropy (randomness) of behavior
    pub fn calculate_entropy(&self) -> f64 {
        let mut entropy = 0.0;
        let mut count = 0;

        if let Some(ref ks) = self.keystroke {
            entropy += ks.entropy();
            count += 1;
        }

        if let Some(ref mouse) = self.mouse {
            entropy += mouse.entropy();
            count += 1;
        }

        if let Some(ref touch) = self.touch {
            entropy += touch.entropy();
            count += 1;
        }

        if count > 0 {
            entropy / count as f64
        } else {
            0.5 // Default entropy
        }
    }
}

impl Default for BehavioralData {
    fn default() -> Self {
        Self::new()
    }
}

/// Keystroke dynamics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeDynamics {
    /// Key press durations (key -> duration in ms)
    pub press_durations: HashMap<char, Vec<u64>>,
    /// Flight times between keys (pair -> duration in ms)
    pub flight_times: HashMap<(char, char), Vec<u64>>,
    /// Total typing time
    pub total_typing_time_ms: u64,
    /// Number of backspaces (corrections)
    pub correction_count: u32,
    /// Typing rhythm consistency (0-1)
    pub rhythm_consistency: f64,
}

impl KeystrokeDynamics {
    /// Create new keystroke dynamics
    pub fn new() -> Self {
        Self {
            press_durations: HashMap::new(),
            flight_times: HashMap::new(),
            total_typing_time_ms: 0,
            correction_count: 0,
            rhythm_consistency: 0.0,
        }
    }

    /// Add key press
    pub fn add_key_press(&mut self, key: char, duration_ms: u64) {
        self.press_durations
            .entry(key)
            .or_insert_with(Vec::new)
            .push(duration_ms);
    }

    /// Add flight time
    pub fn add_flight_time(&mut self, from: char, to: char, duration_ms: u64) {
        self.flight_times
            .entry((from, to))
            .or_insert_with(Vec::new)
            .push(duration_ms);
    }

    /// Calculate average press duration for a key
    pub fn avg_press_duration(&self, key: char) -> Option<f64> {
        self.press_durations
            .get(&key)
            .map(|durations| durations.iter().sum::<u64>() as f64 / durations.len() as f64)
    }

    /// Calculate average flight time between keys
    pub fn avg_flight_time(&self, from: char, to: char) -> Option<f64> {
        self.flight_times
            .get(&(from, to))
            .map(|times| times.iter().sum::<u64>() as f64 / times.len() as f64)
    }

    /// Calculate entropy (measure of randomness/consistency)
    pub fn entropy(&self) -> f64 {
        // Calculate variance in flight times as a measure of consistency
        let all_times: Vec<f64> = self
            .flight_times
            .values()
            .flat_map(|v| v.iter().map(|&t| t as f64))
            .collect();

        if all_times.len() < 2 {
            return 0.5;
        }

        let mean = all_times.iter().sum::<f64>() / all_times.len() as f64;
        let variance =
            all_times.iter().map(|&t| (t - mean).powi(2)).sum::<f64>() / all_times.len() as f64;

        // Normalize: higher variance = lower consistency = higher entropy
        let cv = variance.sqrt() / mean; // Coefficient of variation
        (cv / (1.0 + cv)).min(1.0)
    }

    /// Calculate typing speed (WPM approximation)
    pub fn typing_speed_wpm(&self) -> f64 {
        let total_chars: usize = self.press_durations.values().map(|v| v.len()).sum();
        let minutes = self.total_typing_time_ms as f64 / 60000.0;

        if minutes > 0.0 {
            (total_chars as f64 / 5.0) / minutes // Assuming 5 chars per word
        } else {
            0.0
        }
    }
}

impl Default for KeystrokeDynamics {
    fn default() -> Self {
        Self::new()
    }
}

/// Mouse movement dynamics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseDynamics {
    /// Mouse movement points (x, y, timestamp_ms)
    pub movements: Vec<(f64, f64, u64)>,
    /// Click events (x, y, button, timestamp_ms)
    pub clicks: Vec<(f64, f64, MouseButton, u64)>,
    /// Scroll events
    pub scrolls: Vec<(f64, f64, i32, u64)>, // x, y, delta, time
    /// Average velocity
    pub avg_velocity: f64,
    /// Movement jerkiness (0-1, higher = more robotic)
    pub jerkiness: f64,
}

/// Mouse button
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

impl MouseDynamics {
    /// Create new mouse dynamics
    pub fn new() -> Self {
        Self {
            movements: Vec::new(),
            clicks: Vec::new(),
            scrolls: Vec::new(),
            avg_velocity: 0.0,
            jerkiness: 0.0,
        }
    }

    /// Add movement point
    pub fn add_movement(&mut self, x: f64, y: f64, timestamp_ms: u64) {
        self.movements.push((x, y, timestamp_ms));
    }

    /// Add click
    pub fn add_click(&mut self, x: f64, y: f64, button: MouseButton, timestamp_ms: u64) {
        self.clicks.push((x, y, button, timestamp_ms));
    }

    /// Calculate average velocity
    pub fn calculate_velocity(&self) -> f64 {
        if self.movements.len() < 2 {
            return 0.0;
        }

        let mut total_distance = 0.0;
        let mut total_time = 0u64;

        for window in self.movements.windows(2) {
            let (x1, y1, t1) = window[0];
            let (x2, y2, t2) = window[1];

            let distance = ((x2 - x1).powi(2) + (y2 - y1).powi(2)).sqrt();
            let time = t2.saturating_sub(t1);

            total_distance += distance;
            total_time += time;
        }

        if total_time > 0 {
            total_distance / total_time as f64 * 1000.0 // pixels per second
        } else {
            0.0
        }
    }

    /// Calculate entropy
    pub fn entropy(&self) -> f64 {
        // Use jerkiness as a proxy for entropy
        // Human movements are smooth (low jerkiness), bots are jerky (high jerkiness)
        self.jerkiness
    }

    /// Detect if movement is likely automated
    pub fn is_likely_automated(&self) -> bool {
        // High jerkiness or perfectly straight lines indicate automation
        if self.jerkiness > 0.8 {
            return true;
        }

        // Check for perfectly straight lines (unusual in human movement)
        let mut straight_line_count = 0;
        for window in self.movements.windows(3) {
            let (x1, y1, _) = window[0];
            let (x2, y2, _) = window[1];
            let (x3, y3, _) = window[2];

            // Check if points are collinear
            let slope1 = if x2 != x1 {
                (y2 - y1) / (x2 - x1)
            } else {
                f64::INFINITY
            };
            let slope2 = if x3 != x2 {
                (y3 - y2) / (x3 - x2)
            } else {
                f64::INFINITY
            };

            if (slope1 - slope2).abs() < 0.01 {
                straight_line_count += 1;
            }
        }

        let straight_ratio = straight_line_count as f64 / self.movements.len().max(1) as f64;
        straight_ratio > 0.7 // More than 70% straight lines is suspicious
    }
}

impl Default for MouseDynamics {
    fn default() -> Self {
        Self::new()
    }
}

/// Touch gesture dynamics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TouchDynamics {
    /// Touch events (x, y, pressure, timestamp_ms)
    pub touches: Vec<(f64, f64, f64, u64)>,
    /// Swipe gestures (start_x, start_y, end_x, end_y, duration_ms)
    pub swipes: Vec<(f64, f64, f64, f64, u64)>,
    /// Pinch gestures (scale, duration_ms)
    pub pinches: Vec<(f64, u64)>,
    /// Average touch pressure
    pub avg_pressure: f64,
    /// Touch area consistency
    pub area_consistency: f64,
}

impl TouchDynamics {
    /// Create new touch dynamics
    pub fn new() -> Self {
        Self {
            touches: Vec::new(),
            swipes: Vec::new(),
            pinches: Vec::new(),
            avg_pressure: 0.0,
            area_consistency: 0.0,
        }
    }

    /// Add touch event
    pub fn add_touch(&mut self, x: f64, y: f64, pressure: f64, timestamp_ms: u64) {
        self.touches.push((x, y, pressure, timestamp_ms));
    }

    /// Calculate average pressure
    pub fn calculate_avg_pressure(&self) -> f64 {
        if self.touches.is_empty() {
            return 0.0;
        }
        self.touches.iter().map(|t| t.2).sum::<f64>() / self.touches.len() as f64
    }

    /// Calculate entropy
    pub fn entropy(&self) -> f64 {
        // Use pressure variance as entropy measure
        if self.touches.len() < 2 {
            return 0.5;
        }

        let pressures: Vec<f64> = self.touches.iter().map(|t| t.2).collect();
        let mean = pressures.iter().sum::<f64>() / pressures.len() as f64;
        let variance =
            pressures.iter().map(|&p| (p - mean).powi(2)).sum::<f64>() / pressures.len() as f64;

        let cv = variance.sqrt() / mean;
        (cv / (1.0 + cv)).min(1.0)
    }
}

impl Default for TouchDynamics {
    fn default() -> Self {
        Self::new()
    }
}

/// Scroll event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrollEvent {
    pub timestamp_ms: u64,
    pub delta_x: i32,
    pub delta_y: i32,
    pub scroll_speed: f64,
}

/// Focus event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FocusEvent {
    pub timestamp_ms: u64,
    pub element_id: String,
    pub event_type: FocusEventType,
}

/// Focus event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FocusEventType {
    Focus,
    Blur,
}

/// Behavioral pattern stored for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralPattern {
    /// User ID
    pub user_id: String,
    /// Baseline keystroke dynamics
    pub keystroke_baseline: Option<KeystrokeBaseline>,
    /// Baseline mouse patterns
    pub mouse_baseline: Option<MouseBaseline>,
    /// Baseline touch patterns
    pub touch_baseline: Option<TouchBaseline>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Last updated
    pub last_updated: DateTime<Utc>,
    /// Number of samples used
    pub sample_count: u32,
}

/// Keystroke baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeBaseline {
    /// Average press duration per key
    pub avg_press_durations: HashMap<char, f64>,
    /// Average flight times
    pub avg_flight_times: HashMap<(char, char), f64>,
    /// Standard deviations for press durations
    pub press_std_devs: HashMap<char, f64>,
    /// Standard deviations for flight times
    pub flight_std_devs: HashMap<(char, char), f64>,
    /// Average typing speed (WPM)
    pub avg_typing_speed: f64,
}

/// Mouse baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseBaseline {
    /// Average velocity
    pub avg_velocity: f64,
    /// Velocity standard deviation
    pub velocity_std_dev: f64,
    /// Typical movement patterns
    pub movement_patterns: Vec<Vec<(f64, f64)>>,
}

/// Touch baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TouchBaseline {
    /// Average pressure
    pub avg_pressure: f64,
    /// Pressure standard deviation
    pub pressure_std_dev: f64,
    /// Typical swipe patterns
    pub swipe_patterns: Vec<(f64, f64, f64, f64)>, // start_x, start_y, end_x, end_y
}

/// Behavioral score result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralScore {
    /// Match score (0-1, higher = better match)
    pub match_score: f64,
    /// Confidence in score (0-1)
    pub confidence: f64,
    /// Contributing factors
    pub factors: Vec<BehavioralFactor>,
    /// Is likely impostor
    pub is_likely_impostor: bool,
    /// Risk contribution (0-100)
    pub risk_score: u8,
}

impl BehavioralScore {
    /// Get risk contribution for overall risk scoring
    pub fn risk_contribution(&self) -> u8 {
        if self.is_likely_impostor {
            40 // High risk if likely impostor
        } else {
            (100 - (self.match_score * 100.0) as u8).min(20) // Up to 20 for low match
        }
    }
}

/// Individual behavioral factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFactor {
    /// Factor type
    pub factor_type: String,
    /// Score contribution
    pub contribution: f64,
    /// Description
    pub description: String,
}

/// Behavioral biometrics analyzer
pub struct BehavioralBiometrics {
    /// Model manager
    model_manager: Arc<ModelManager>,
    /// Database connection
    db: DbContext,
    /// User patterns cache
    patterns: Arc<RwLock<HashMap<String, BehavioralPattern>>>,
    /// Recent behavioral data
    recent_data: Arc<RwLock<HashMap<String, VecDeque<BehavioralData>>>>,
}

impl BehavioralBiometrics {
    /// Create new behavioral biometrics analyzer
    pub async fn new(model_manager: Arc<ModelManager>, db: DbContext) -> AiResult<Self> {
        Ok(Self {
            model_manager,
            db,
            patterns: Arc::new(RwLock::new(HashMap::new())),
            recent_data: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Analyze behavioral data against user's baseline
    pub async fn analyze(&self, user_id: &str, data: &BehavioralData) -> AiResult<BehavioralScore> {
        // Load user's baseline pattern
        let pattern = self.load_pattern(user_id).await?;

        let mut factors = Vec::new();
        let mut match_scores = Vec::new();

        // Analyze keystroke dynamics
        if let (Some(ref baseline), Some(ref current)) =
            (pattern.keystroke_baseline, &data.keystroke)
        {
            let ks_score = self.compare_keystroke(baseline, current);
            match_scores.push(ks_score);

            if ks_score < 0.5 {
                factors.push(BehavioralFactor {
                    factor_type: "keystroke".to_string(),
                    contribution: 1.0 - ks_score,
                    description: "Keystroke pattern differs from baseline".to_string(),
                });
            }
        }

        // Analyze mouse dynamics
        if let (Some(ref baseline), Some(ref current)) = (pattern.mouse_baseline, &data.mouse) {
            let mouse_score = self.compare_mouse(baseline, current);
            match_scores.push(mouse_score);

            if mouse_score < 0.5 {
                factors.push(BehavioralFactor {
                    factor_type: "mouse".to_string(),
                    contribution: 1.0 - mouse_score,
                    description: "Mouse movement pattern differs from baseline".to_string(),
                });
            }
        }

        // Analyze touch dynamics
        if let (Some(ref baseline), Some(ref current)) = (pattern.touch_baseline, &data.touch) {
            let touch_score = self.compare_touch(baseline, current);
            match_scores.push(touch_score);

            if touch_score < 0.5 {
                factors.push(BehavioralFactor {
                    factor_type: "touch".to_string(),
                    contribution: 1.0 - touch_score,
                    description: "Touch gesture pattern differs from baseline".to_string(),
                });
            }
        }

        // Calculate overall match score
        let overall_match = if match_scores.is_empty() {
            0.5 // Neutral if no data
        } else {
            match_scores.iter().sum::<f64>() / match_scores.len() as f64
        };

        // Check for automated behavior
        let is_automated = data
            .mouse
            .as_ref()
            .map_or(false, |m| m.is_likely_automated());

        let is_likely_impostor = overall_match < 0.3 || is_automated;
        let risk_score = if is_automated {
            80
        } else if is_likely_impostor {
            60
        } else {
            ((1.0 - overall_match) * 40.0) as u8 // Up to 40 for low match
        };

        let confidence = if match_scores.len() >= 3 {
            0.9
        } else if match_scores.len() >= 2 {
            0.7
        } else {
            0.5
        };

        Ok(BehavioralScore {
            match_score: overall_match,
            confidence,
            factors,
            is_likely_impostor,
            risk_score,
        })
    }

    /// Record behavioral data for baseline learning
    pub async fn record(&self, user_id: &str, data: &BehavioralData) -> AiResult<()> {
        let mut recent = self.recent_data.write().await;
        let entry = recent
            .entry(user_id.to_string())
            .or_insert_with(VecDeque::new);

        entry.push_back(data.clone());

        // Keep last 10 samples
        while entry.len() > 10 {
            entry.pop_front();
        }

        // Update baseline if we have enough samples
        if entry.len() >= 5 {
            self.update_baseline(user_id, entry).await?;
        }

        Ok(())
    }

    /// Load user's behavioral pattern
    async fn load_pattern(&self, user_id: &str) -> AiResult<BehavioralPattern> {
        // Check cache
        {
            let patterns = self.patterns.read().await;
            if let Some(pattern) = patterns.get(user_id) {
                return Ok(pattern.clone());
            }
        }

        // Create new pattern
        let pattern = BehavioralPattern {
            user_id: user_id.to_string(),
            keystroke_baseline: None,
            mouse_baseline: None,
            touch_baseline: None,
            created_at: Utc::now(),
            last_updated: Utc::now(),
            sample_count: 0,
        };

        // Cache it
        let mut patterns = self.patterns.write().await;
        patterns.insert(user_id.to_string(), pattern.clone());

        Ok(pattern)
    }

    /// Update baseline from recent data
    async fn update_baseline(
        &self,
        user_id: &str,
        samples: &VecDeque<BehavioralData>,
    ) -> AiResult<()> {
        let mut patterns = self.patterns.write().await;

        if let Some(pattern) = patterns.get_mut(user_id) {
            // Build keystroke baseline
            let keystroke_samples: Vec<_> = samples
                .iter()
                .filter_map(|s| s.keystroke.as_ref())
                .collect();

            if !keystroke_samples.is_empty() {
                pattern.keystroke_baseline =
                    Some(self.build_keystroke_baseline(&keystroke_samples));
            }

            // Build mouse baseline
            let mouse_samples: Vec<_> = samples.iter().filter_map(|s| s.mouse.as_ref()).collect();

            if !mouse_samples.is_empty() {
                pattern.mouse_baseline = Some(self.build_mouse_baseline(&mouse_samples));
            }

            // Build touch baseline
            let touch_samples: Vec<_> = samples.iter().filter_map(|s| s.touch.as_ref()).collect();

            if !touch_samples.is_empty() {
                pattern.touch_baseline = Some(self.build_touch_baseline(&touch_samples));
            }

            pattern.sample_count = samples.len() as u32;
            pattern.last_updated = Utc::now();
        }

        Ok(())
    }

    /// Build keystroke baseline from samples
    fn build_keystroke_baseline(&self, samples: &[&KeystrokeDynamics]) -> KeystrokeBaseline {
        let mut avg_press_durations: HashMap<char, f64> = HashMap::new();
        let mut avg_flight_times: HashMap<(char, char), f64> = HashMap::new();

        // Aggregate press durations
        for sample in samples {
            for (key, durations) in &sample.press_durations {
                if !durations.is_empty() {
                    let avg = durations.iter().sum::<u64>() as f64 / durations.len() as f64;
                    avg_press_durations
                        .entry(*key)
                        .and_modify(|v| *v = (*v + avg) / 2.0)
                        .or_insert(avg);
                }
            }
        }

        // Aggregate flight times
        for sample in samples {
            for (keys, times) in &sample.flight_times {
                if !times.is_empty() {
                    let avg = times.iter().sum::<u64>() as f64 / times.len() as f64;
                    avg_flight_times
                        .entry(*keys)
                        .and_modify(|v| *v = (*v + avg) / 2.0)
                        .or_insert(avg);
                }
            }
        }

        KeystrokeBaseline {
            avg_press_durations,
            avg_flight_times,
            press_std_devs: HashMap::new(), // Would calculate from data
            flight_std_devs: HashMap::new(),
            avg_typing_speed: 40.0, // Default WPM
        }
    }

    /// Build mouse baseline from samples
    fn build_mouse_baseline(&self, samples: &[&MouseDynamics]) -> MouseBaseline {
        let velocities: Vec<f64> = samples.iter().map(|s| s.calculate_velocity()).collect();
        let avg_velocity = velocities.iter().sum::<f64>() / velocities.len() as f64;

        MouseBaseline {
            avg_velocity,
            velocity_std_dev: 0.0, // Would calculate
            movement_patterns: Vec::new(),
        }
    }

    /// Build touch baseline from samples
    fn build_touch_baseline(&self, samples: &[&TouchDynamics]) -> TouchBaseline {
        let pressures: Vec<f64> = samples.iter().map(|s| s.calculate_avg_pressure()).collect();
        let avg_pressure = pressures.iter().sum::<f64>() / pressures.len() as f64;

        TouchBaseline {
            avg_pressure,
            pressure_std_dev: 0.0,
            swipe_patterns: Vec::new(),
        }
    }

    /// Compare keystroke against baseline
    fn compare_keystroke(&self, baseline: &KeystrokeBaseline, current: &KeystrokeDynamics) -> f64 {
        let mut scores = Vec::new();

        // Compare typing speed
        let current_speed = current.typing_speed_wpm();
        let speed_diff = (current_speed - baseline.avg_typing_speed).abs();
        let speed_score = 1.0 - (speed_diff / 100.0).min(1.0);
        scores.push(speed_score);

        // Compare key press durations (if available)
        let mut press_matches = 0;
        let mut press_total = 0;
        for (key, durations) in &current.press_durations {
            if let Some(&baseline_avg) = baseline.avg_press_durations.get(key) {
                if let Some(current_avg) = current.avg_press_duration(*key) {
                    let diff = (current_avg - baseline_avg).abs();
                    let score = 1.0 - (diff / 200.0).min(1.0); // 200ms difference = 0 match
                    scores.push(score);
                    press_matches += 1;
                }
            }
            press_total += 1;
        }

        if scores.is_empty() {
            return 0.5;
        }

        scores.iter().sum::<f64>() / scores.len() as f64
    }

    /// Compare mouse against baseline
    fn compare_mouse(&self, baseline: &MouseBaseline, current: &MouseDynamics) -> f64 {
        let current_velocity = current.calculate_velocity();
        let velocity_diff = (current_velocity - baseline.avg_velocity).abs();
        1.0 - (velocity_diff / 1000.0).min(1.0) // 1000 px/s difference = 0 match
    }

    /// Compare touch against baseline
    fn compare_touch(&self, baseline: &TouchBaseline, current: &TouchDynamics) -> f64 {
        let current_pressure = current.calculate_avg_pressure();
        let pressure_diff = (current_pressure - baseline.avg_pressure).abs();
        1.0 - (pressure_diff / 0.5).min(1.0) // 0.5 pressure diff = 0 match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystroke_dynamics() {
        let mut ks = KeystrokeDynamics::new();

        ks.add_key_press('a', 100);
        ks.add_key_press('a', 120);
        ks.add_flight_time('a', 'b', 50);
        ks.add_flight_time('a', 'b', 60);

        assert_eq!(ks.avg_press_duration('a'), Some(110.0));
        assert_eq!(ks.avg_flight_time('a', 'b'), Some(55.0));

        let entropy = ks.entropy();
        assert!(entropy >= 0.0 && entropy <= 1.0);
    }

    #[test]
    fn test_mouse_dynamics() {
        let mut mouse = MouseDynamics::new();

        mouse.add_movement(0.0, 0.0, 0);
        mouse.add_movement(10.0, 10.0, 100);
        mouse.add_click(10.0, 10.0, MouseButton::Left, 100);

        let velocity = mouse.calculate_velocity();
        assert!(velocity >= 0.0);

        assert!(!mouse.is_likely_automated());
    }

    #[test]
    fn test_behavioral_data() {
        let data = BehavioralData::new()
            .with_keystroke(KeystrokeDynamics::new())
            .with_mouse(MouseDynamics::new());

        assert!(data.has_biometrics());
        assert!(data.keystroke.is_some());
        assert!(data.mouse.is_some());
    }

    #[test]
    fn test_behavioral_score() {
        let score = BehavioralScore {
            match_score: 0.3,
            confidence: 0.8,
            factors: vec![],
            is_likely_impostor: true,
            risk_score: 60,
        };

        assert_eq!(score.risk_contribution(), 40);

        let score2 = BehavioralScore {
            match_score: 0.8,
            confidence: 0.7,
            factors: vec![],
            is_likely_impostor: false,
            risk_score: 20,
        };

        assert_eq!(score2.risk_contribution(), 20);
    }
}
