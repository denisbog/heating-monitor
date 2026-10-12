//! Dashboard layout: how many charts the page shows and what is on each.
//!
//! The layout is one JSON document stored in the `settings` table
//! (`key = 'dashboard'`), so it is shared by every client instead of living in
//! one browser's `localStorage`. Reading it needs any valid token; changing it
//! needs the admin `API_TOKEN` (see `lib.rs`).

use serde::{Deserialize, Serialize};

/// Hard cap on configured charts, so one request cannot bloat the D1 row or
/// the public page.
pub const MAX_CHARTS: usize = 24;
/// Hard cap on series per chart.
pub const MAX_METRICS: usize = 12;
/// `settings` row that holds the layout.
pub const SETTINGS_KEY: &str = "dashboard";

/// One configured chart card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartSpec {
    /// Card heading; empty falls back to a generated title.
    #[serde(default)]
    pub title: String,
    /// Device id to plot, or empty to plot every device that has the metric.
    #[serde(default)]
    pub device: String,
    /// Metrics drawn as series.
    #[serde(default)]
    pub metrics: Vec<String>,
    /// Axis/tooltip unit override; empty takes the unit stored with the reading.
    #[serde(default)]
    pub unit: String,
    /// `line` (default), `area` or `bar`.
    #[serde(default)]
    pub kind: String,
}

/// The whole layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    #[serde(default = "version_one")]
    pub version: u32,
    /// Optional page title shown above the charts.
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub charts: Vec<ChartSpec>,
}

fn version_one() -> u32 {
    1
}

impl Default for Dashboard {
    fn default() -> Self {
        Self {
            version: 1,
            title: String::new(),
            charts: Vec::new(),
        }
    }
}

impl Dashboard {
    /// Clamp a submitted layout to values we are willing to store:
    /// bounded counts, trimmed strings, a known chart kind, and no chart
    /// without metrics (it would render as an empty card).
    pub fn sanitize(mut self) -> Self {
        const TEXT: usize = 120;
        self.version = 1;
        self.title = self.title.trim().chars().take(TEXT).collect();
        self.charts.truncate(MAX_CHARTS);
        for c in &mut self.charts {
            c.title = c.title.trim().chars().take(TEXT).collect();
            c.device = c.device.trim().chars().take(TEXT).collect();
            c.unit = c.unit.trim().chars().take(24).collect();
            c.kind = match c.kind.trim() {
                "area" => "area",
                "bar" => "bar",
                _ => "line",
            }
            .to_string();
            let metrics = std::mem::take(&mut c.metrics);
            c.metrics = metrics
                .into_iter()
                .map(|m| m.trim().chars().take(TEXT).collect::<String>())
                .filter(|m| !m.is_empty())
                .take(MAX_METRICS)
                .collect();
        }
        self.charts.retain(|c| !c.metrics.is_empty());
        self
    }
}
