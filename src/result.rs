use crate::model::Domain;
use std::time::Duration;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Scan status of current scanner
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ScanStatus {
    Ready,
    Done,
    Timeout,
    Error,
}

/// Result of domain scan  
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DomainScanResult {
    /// HashMap of domain.
    ///
    /// (Domain, IP Addresses)
    pub domains: Vec<Domain>,
    /// Time from start to end of scan.  
    pub scan_time: Duration,
    /// Scan job status
    pub scan_status: ScanStatus,
}

impl DomainScanResult {
    pub fn new() -> DomainScanResult {
        DomainScanResult {
            domains: vec![],
            scan_time: Duration::from_millis(0),
            scan_status: ScanStatus::Ready,
        }
    }
}
