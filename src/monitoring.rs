#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub name: String,
    pub severity: AlertSeverity,
    pub threshold: f64,
    pub window_seconds: u64,
    pub enabled: bool,
}

/// Alert event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub name: String,
    pub severity: AlertSeverity,
    pub message: String,
    pub timestamp: i64,
    pub value: f64,
    pub metadata: HashMap<String, String>,
}

/// Monitoring and alerting system
pub struct MonitoringService {
    alerts: Arc<RwLock<Vec<Alert>>>,
    configs: Arc<RwLock<HashMap<String, AlertConfig>>>,
    metrics_history: Arc<RwLock<HashMap<String, Vec<(i64, f64)>>>>,
}

impl MonitoringService {
    pub fn new() -> Self {
        let mut configs = HashMap::new();
        
        // Default alert configurations
        configs.insert(
            "high_error_rate".to_string(),
            AlertConfig {
                name: "high_error_rate".to_string(),
                severity: AlertSeverity::Error,
                threshold: 0.05, // 5% error rate
                window_seconds: 300, // 5 minutes
                enabled: true,
            },
        );
        
        configs.insert(
            "slow_response_time".to_string(),
            AlertConfig {
                name: "slow_response_time".to_string(),
                severity: AlertSeverity::Warning,
                threshold: 1000.0, // 1 second
                window_seconds: 60,
                enabled: true,
            },
        );
        
        configs.insert(
            "high_memory_usage".to_string(),
            AlertConfig {
                name: "high_memory_usage".to_string(),
                severity: AlertSeverity::Warning,
                threshold: 0.85, // 85%
                window_seconds: 300,
                enabled: true,
            },
        );
        
        configs.insert(
            "redis_connection_failure".to_string(),
            AlertConfig {
                name: "redis_connection_failure".to_string(),
                severity: AlertSeverity::Critical,
                threshold: 1.0, // Any failure
                window_seconds: 60,
                enabled: true,
            },
        );
        
        configs.insert(
            "order_matching_backlog".to_string(),
            AlertConfig {
                name: "order_matching_backlog".to_string(),
                severity: AlertSeverity::Warning,
                threshold: 1000.0, // 1000 pending orders
                window_seconds: 300,
                enabled: true,
            },
        );

        Self {
            alerts: Arc::new(RwLock::new(Vec::new())),
            configs: Arc::new(RwLock::new(configs)),
            metrics_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a metric value
    pub async fn record_metric(&self, name: &str, value: f64) {
        let timestamp = chrono::Utc::now().timestamp();
        let mut history = self.metrics_history.write().await;
        
        let entry = history.entry(name.to_string()).or_insert_with(Vec::new);
        entry.push((timestamp, value));
        
        // Keep only last hour of data
        let cutoff = timestamp - 3600;
        entry.retain(|(ts, _)| *ts > cutoff);
        
        // Check if this triggers any alerts
        drop(history);
        self.check_alerts(name, value).await;
    }

    /// Check if metric triggers any alerts
    async fn check_alerts(&self, metric_name: &str, current_value: f64) {
        let configs = self.configs.read().await;
        
        let mut triggered_alerts = Vec::new();
        
        for (alert_name, config) in configs.iter() {
            if !config.enabled {
                continue;
            }
            
            // Simple threshold check for now
            if current_value > config.threshold {
                triggered_alerts.push(Alert {
                    name: alert_name.clone(),
                    severity: config.severity,
                    message: format!(
                        "{} exceeded threshold: {} > {}",
                        metric_name, current_value, config.threshold
                    ),
                    timestamp: chrono::Utc::now().timestamp(),
                    value: current_value,
                    metadata: HashMap::new(),
                });
            }
        }
        
        drop(configs);
        
        // Trigger all alerts after releasing the lock
        for alert in triggered_alerts {
            self.trigger_alert(alert).await;
        }
    }

    /// Trigger an alert
    pub async fn trigger_alert(&self, alert: Alert) {
        match alert.severity {
            AlertSeverity::Info => info!(
                alert = %alert.name,
                value = %alert.value,
                "{}",
                alert.message
            ),
            AlertSeverity::Warning => warn!(
                alert = %alert.name,
                value = %alert.value,
                "{}",
                alert.message
            ),
            AlertSeverity::Error | AlertSeverity::Critical => error!(
                alert = %alert.name,
                value = %alert.value,
                severity = ?alert.severity,
                "{}",
                alert.message
            ),
        }

        // Store alert
        let mut alerts = self.alerts.write().await;
        alerts.push(alert.clone());
        
        // Keep only last 1000 alerts
        if alerts.len() > 1000 {
            let len = alerts.len();
            alerts.drain(0..len - 1000);
        }
        
        let alert_payload = serde_json::json!({
            "name": alert.name,
            "severity": format!("{:?}", alert.severity),
            "message": alert.message,
            "timestamp": alert.timestamp,
            "value": alert.value,
            "metadata": alert.metadata,
        });

        let targets = [
            std::env::var("ALERT_WEBHOOK_URL").ok(),
            std::env::var("SLACK_WEBHOOK_URL").ok(),
            std::env::var("PAGERDUTY_WEBHOOK_URL").ok(),
            std::env::var("EMAIL_ALERT_WEBHOOK_URL").ok(),
        ];

        for url in targets.into_iter().flatten() {
            let payload = alert_payload.clone();
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                if let Err(e) = client.post(url).json(&payload).send().await {
                    tracing::warn!(error = %e, "Failed to send external alert webhook");
                }
            });
        }
    }

    /// Get recent alerts
    pub async fn get_recent_alerts(&self, limit: usize) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts.iter().rev().take(limit).cloned().collect()
    }

    /// Get alert history for specific alert
    pub async fn get_alert_history(&self, alert_name: &str, limit: usize) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts
            .iter()
            .filter(|a| a.name == alert_name)
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Update alert configuration
    pub async fn update_alert_config(&self, config: AlertConfig) {
        let mut configs = self.configs.write().await;
        configs.insert(config.name.clone(), config);
    }

    /// Get all alert configurations
    pub async fn get_alert_configs(&self) -> HashMap<String, AlertConfig> {
        self.configs.read().await.clone()
    }

    /// Check system health
    pub async fn check_health(&self) -> HashMap<String, String> {
        let mut health = HashMap::new();
        
        // Check recent critical alerts
        let alerts = self.alerts.read().await;
        let recent_critical = alerts
            .iter()
            .filter(|a| {
                a.severity == AlertSeverity::Critical
                    && a.timestamp > chrono::Utc::now().timestamp() - 300
            })
            .count();
        
        health.insert(
            "recent_critical_alerts".to_string(),
            recent_critical.to_string(),
        );
        
        health.insert(
            "total_alerts".to_string(),
            alerts.len().to_string(),
        );
        
        health.insert(
            "monitoring_status".to_string(),
            "active".to_string(),
        );
        
        health
    }
}

impl Default for MonitoringService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monitoring_creation() {
        let monitor = MonitoringService::new();
        let configs = monitor.get_alert_configs().await;
        
        assert!(configs.contains_key("high_error_rate"));
        assert!(configs.contains_key("redis_connection_failure"));
    }

    #[tokio::test]
    async fn test_record_metric() {
        let monitor = MonitoringService::new();
        
        monitor.record_metric("test_metric", 50.0).await;
        
        let history = monitor.metrics_history.read().await;
        assert!(history.contains_key("test_metric"));
        assert_eq!(history.get("test_metric").unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_alert_trigger() {
        let monitor = MonitoringService::new();
        
        // Should trigger high_error_rate alert (threshold 0.05)
        monitor.record_metric("high_error_rate", 0.10).await;
        
        let alerts = monitor.get_recent_alerts(10).await;
        assert!(!alerts.is_empty());
    }

    #[tokio::test]
    async fn test_update_config() {
        let monitor = MonitoringService::new();
        
        let config = AlertConfig {
            name: "test_alert".to_string(),
            severity: AlertSeverity::Info,
            threshold: 100.0,
            window_seconds: 60,
            enabled: true,
        };
        
        monitor.update_alert_config(config.clone()).await;
        
        let configs = monitor.get_alert_configs().await;
        assert!(configs.contains_key("test_alert"));
    }
}
