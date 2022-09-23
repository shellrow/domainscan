use std::net::IpAddr;
use std::time::{Duration};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertEntry {
    pub id: u64,
    pub issuer_ca_id: u32,
    pub issuer_name: String,
    pub common_name: String,
    pub name_value: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_number: String,
    pub entry_timestamp: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Domain {
    pub domain_name: String,
    pub ips: Vec<IpAddr>,
}

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
