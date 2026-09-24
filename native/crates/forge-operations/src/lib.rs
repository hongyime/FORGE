//! `forge-operations` — Monitoring, alerts, remediation, retention, workspace and automation (T21–T24).
//!
//! # Modules
//!
//! - `monitoring` — T21: `MonitoringPolicy`, `Alert`, `ExposureMetric`, `MonitoringSnapshot`.
//! - `remediation` — T22: `RemediationItem`, `TicketEvent`, retest lifecycle.
//! - `operations` — T23: `RetentionPolicy`, `WorkspaceRecord`, automation state.
//! - `parity` — T24: `ParityReceipt`, `LedgerCheck`, service-parity verification.

pub mod monitoring;
pub mod remediation;

pub use monitoring::{
    Alert, AlertSeverity, AlertStatus, ExposureMetric, MonitoringPolicy, MonitoringSnapshot,
    PolicyMode, PolicyStatus,
};

pub use remediation::{
    RemediationItem, RemediationStatus, RiskAcceptance, RiskAcceptanceState,
    TicketEvent, TicketEventStatus, TicketKind,
};
