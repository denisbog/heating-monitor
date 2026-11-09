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
    /// Where the series come from: `cloud` (default — the provider `readings`
    /// table, i.e. the heat pump and thermostats) or `ingest` (the samples the
    /// eink-x devices push to `/v1/samples`).
    #[serde(default)]
    pub source: String,
    /// Device id to plot, or empty to plot every device that has the metric.
    #[serde(default)]
    pub device: String,
    /// Ingest charts only: plot a single `node_id`; empty plots every node,
    /// each as its own series. Mesh devices send samples under several node
    /// ids, so this is what lets one chart show node 7 next to node 9.
    #[serde(default)]
    pub node: String,
    /// Metrics drawn as series.
    #[serde(default)]
    pub metrics: Vec<String>,
    /// Axis/tooltip unit override; empty takes the unit stored with the reading.
    #[serde(default)]
    pub unit: String,
    /// `line` (default), `area` or `bar`.
    #[serde(default)]
    pub kind: String,
    /// Ingest charts only: which of the two stored clocks is the x axis.
    /// `received` (default) is the server clock at upload; `device` is the
    /// untrusted `device_collected_at` the firmware reported when it queued the
    /// sample. Empty rows for the chosen clock are skipped.
    #[serde(default)]
    pub time: String,
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
            c.source = match c.source.trim() {
                "ingest" => "ingest",
                _ => "cloud",
            }
            .to_string();
            c.time = match c.time.trim() {
                "device" => "device",
                _ => "received",
            }
            .to_string();
            c.device = c.device.trim().chars().take(TEXT).collect();
            // Node ids are 1..254; anything else means "every node".
            c.node = c
                .node
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|n| *n > 0)
                .map(|n| n.to_string())
                .unwrap_or_default();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_layouts_default_to_cloud_and_upload_time() {
        // A layout stored before ingest charts existed has neither field.
        let cfg: Dashboard =
            serde_json::from_str(r#"{"version":1,"charts":[{"metrics":["t_out"]}]}"#).unwrap();
        assert_eq!(cfg.charts[0].source, "");
        let cfg = cfg.sanitize();
        assert_eq!(cfg.charts[0].source, "cloud");
        assert_eq!(cfg.charts[0].time, "received");
    }

    #[test]
    fn ingest_source_and_timeline_are_kept() {
        let cfg = serde_json::from_str::<Dashboard>(
            r#"{"charts":[{"source":"ingest","time":"device","metrics":["temperature"]}]}"#,
        )
        .unwrap()
        .sanitize();
        assert_eq!(cfg.charts[0].source, "ingest");
        assert_eq!(cfg.charts[0].time, "device");
    }

    #[test]
    fn node_filter_is_normalised_or_dropped() {
        let cfg = serde_json::from_str::<Dashboard>(
            r#"{"charts":[
                {"source":"ingest","node":" 7 ","metrics":["temperature"]},
                {"source":"ingest","node":"abc","metrics":["humidity"]},
                {"source":"ingest","metrics":["battery"]}
            ]}"#,
        )
        .unwrap()
        .sanitize();
        assert_eq!(cfg.charts[0].node, "7");
        assert_eq!(cfg.charts[1].node, "");
        assert_eq!(cfg.charts[2].node, "");
    }

    #[test]
    fn unknown_source_and_timeline_fall_back() {
        let cfg = serde_json::from_str::<Dashboard>(
            r#"{"charts":[{"source":" samples ","time":"collected","metrics":["humidity"]}]}"#,
        )
        .unwrap()
        .sanitize();
        assert_eq!(cfg.charts[0].source, "cloud");
        assert_eq!(cfg.charts[0].time, "received");
    }
}
