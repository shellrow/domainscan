use std::time::{Duration};
use serde::{Deserialize, Serialize};
use crate::model::Domain;

/// Scan status of current scanner
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ScanStatus {
    Ready,
    Done,
    Timeout,
    Error,
}

/// Result of domain scan  
#[derive(Serialize, Deserialize, Debug, Clone)]
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
