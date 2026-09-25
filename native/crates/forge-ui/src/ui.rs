//! Rust UI scaffold — Leptos SSR routes, overview and engagement detail (T28–T30).
//!
//! Ports the server-rendered UI structure from `forge/webui/`:
//! - Overview page: workspace list, engagement filter/search
//! - Engagement detail: tabs (seeds/findings/graph/report/audit)
//! - Workspace administration panel
//!
//! # Key invariants
//!
//! - Every route requires JWT authentication (injected by `forge-server::api`).
//! - Secret-bearing fields are never rendered — display strings only.
//! - SSR fragments degrade gracefully when data is unavailable.

use serde::{Deserialize, Serialize};

// ─── UIRoute ──────────────────────────────────────────────────────────────────

/// Server-side rendered routes. Matches `forge/webui/routes.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UIRoute {
    /// `/` — workspace overview with engagement list.
    Overview,
    /// `/engagements/{ref}` — engagement detail.
    EngagementDetail,
    /// `/engagements/{ref}/tab/{name}` — HTMX fragment for a detail tab.
    EngagementTab,
    /// `/workspaces` — workspace administration.
    WorkspaceAdmin,
    /// `/login` — JWT token request.
    Login,
    /// `/health` — loopback health page.
    Health,
}

impl UIRoute {
    pub fn path_template(self) -> &'static str {
        match self {
            Self::Overview          => "/",
            Self::EngagementDetail  => "/engagements/{ref}",
            Self::EngagementTab     => "/engagements/{ref}/tab/{name}",
            Self::WorkspaceAdmin    => "/workspaces",
            Self::Login             => "/login",
            Self::Health            => "/health",
        }
    }

    pub fn requires_auth(self) -> bool {
        !matches!(self, Self::Login | Self::Health)
    }
}

// ─── EngagementSummary ────────────────────────────────────────────────────────

/// Overview-level summary for one engagement (no raw secrets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementSummary {
    pub id: i64,
    pub title: String,
    pub workspace_id: String,
    pub seed_count: usize,
    pub reportable_count: usize,
    pub last_run_at: Option<f64>,
    pub status: EngagementStatus,
}

/// Run status visible in the overview table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngagementStatus {
    Running,
    Completed,
    Failed,
    Paused,
    New,
}

impl EngagementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running   => "running",
            Self::Completed => "completed",
            Self::Failed    => "failed",
            Self::Paused    => "paused",
            Self::New       => "new",
        }
    }
}

// ─── OverviewView ─────────────────────────────────────────────────────────────

/// Data model for the workspace overview page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewView {
    pub workspace_id: String,
    pub engagements: Vec<EngagementSummary>,
    pub total_count: usize,
    pub page: usize,
    pub page_size: usize,
}

impl OverviewView {
    pub fn empty(workspace_id: impl Into<String>) -> Self {
        Self {
            workspace_id: workspace_id.into(),
            engagements: Vec::new(),
            total_count: 0,
            page: 1,
            page_size: 25,
        }
    }

    pub fn page_count(&self) -> usize {
        if self.total_count == 0 || self.page_size == 0 {
            return 1;
        }
        self.total_count.div_ceil(self.page_size)
    }
}

// ─── DetailTab ────────────────────────────────────────────────────────────────

/// Named tabs in the engagement detail view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetailTab {
    Overview,
    Seeds,
    Findings,
    Graph,
    Report,
    Audit,
    ActiveValidation,
    Remediation,
}

impl DetailTab {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Overview          => "overview",
            Self::Seeds             => "seeds",
            Self::Findings          => "findings",
            Self::Graph             => "graph",
            Self::Report            => "report",
            Self::Audit             => "audit",
            Self::ActiveValidation  => "active-validation",
            Self::Remediation       => "remediation",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "overview"          => Some(Self::Overview),
            "seeds"             => Some(Self::Seeds),
            "findings"          => Some(Self::Findings),
            "graph"             => Some(Self::Graph),
            "report"            => Some(Self::Report),
            "audit"             => Some(Self::Audit),
            "active-validation" => Some(Self::ActiveValidation),
            "remediation"       => Some(Self::Remediation),
            _                   => None,
        }
    }
}

// ─── EngagementDetailView ────────────────────────────────────────────────────

/// Data model for the engagement detail page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementDetailView {
    pub engagement_id: i64,
    pub title: String,
    pub workspace_id: String,
    pub active_tab: DetailTab,
    pub summary: EngagementSummary,
}

// ─── WorkspacePanel ──────────────────────────────────────────────────────────

/// Data model for the workspace administration panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspacePanel {
    pub workspace_id: String,
    pub name: String,
    pub member_count: usize,
    pub engagement_count: usize,
}

// ─── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_route_paths() {
        assert_eq!(UIRoute::Overview.path_template(), "/");
        assert_eq!(UIRoute::Login.path_template(), "/login");
    }

    #[test]
    fn login_no_auth() {
        assert!(!UIRoute::Login.requires_auth());
        assert!(!UIRoute::Health.requires_auth());
        assert!(UIRoute::Overview.requires_auth());
        assert!(UIRoute::EngagementDetail.requires_auth());
    }

    #[test]
    fn engagement_status_str() {
        assert_eq!(EngagementStatus::Running.as_str(),   "running");
        assert_eq!(EngagementStatus::Completed.as_str(), "completed");
    }

    #[test]
    fn overview_view_page_count() {
        let mut v = OverviewView::empty("ws1");
        v.total_count = 51;
        v.page_size   = 25;
        assert_eq!(v.page_count(), 3); // ceil(51/25)
    }

    #[test]
    fn detail_tab_round_trip() {
        for s in ["overview","seeds","findings","graph","report","audit","active-validation","remediation"] {
            let t = DetailTab::from_str(s).expect("known tab");
            assert_eq!(t.as_str(), s);
        }
    }

    #[test]
    fn detail_tab_unknown() {
        assert_eq!(DetailTab::from_str("unknown-tab"), None);
    }
}
