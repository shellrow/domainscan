use std::time::{Duration, Instant};
use std::sync::{Mutex, Arc};
use std::sync::mpsc::{channel ,Sender, Receiver};
use tokio::time::{timeout};
//use reqwest::Url;
//use reqwest::header::USER_AGENT;
use crate::model::{Domain, ScanStatus,DomainScanResult};
//use crate::config::{URL_CRT, DEFAULT_USER_AGENT};

/// Structure for domain scan  
/// 
/// Should be constructed using DomainScanner::new
#[derive(Clone)]
pub struct DomainScanner {
    /// Base Domain Name of scan target.  
    base_domain: String,
    /// Word-list of name
    word_list: Vec<String>,
    /// Timeout setting of domain scan.  
    timeout: Duration,
    /// Result of domain scan.  
    scan_result: DomainScanResult,
    /// Sender for progress messaging
    tx: Arc<Mutex<Sender<String>>>,
    /// Receiver for progress messaging
    rx: Arc<Mutex<Receiver<String>>>,
    /// Run passive scan
    passive: bool,
}

impl DomainScanner {
    /// Construct new UriScanner  
    pub fn new() -> Result<DomainScanner, String> {
        let (tx, rx) = channel();
        let domain_scanner = DomainScanner {
            base_domain: String::new(),
            word_list: vec![],
            timeout: Duration::from_millis(30000),
            scan_result: DomainScanResult::new(),
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
            passive: false,
        };
        Ok(domain_scanner)
    }
    /// Set base Domain of scan target.  
    pub fn set_base_domain(&mut self, base_domain: String) {
        self.base_domain = base_domain;
    }
    /// Add word to word-list
    pub fn add_word(&mut self, word: String) {
        self.word_list.push(word);
    }
    /// Set scan timeout  
    pub fn set_timeout(&mut self, timeout: Duration){
        self.timeout = timeout;
    }
    /// Run scan with current settings. 
    /// 
    /// Results are stored in DomainScanner::scan_result
    pub async fn run_scan(&mut self){
        let start_time = Instant::now();
        let res = if self.passive {
            timeout(self.timeout, scan_domain_passive(self.base_domain.clone(), &self.tx)).await
        }else{
            timeout(self.timeout, scan_domain(self.base_domain.clone(), self.word_list.clone(), &self.tx)).await
        };
        match res {
            Ok(domains) => {
                self.scan_result.domains = domains;
                self.scan_result.scan_status = ScanStatus::Done;
            },
            Err(_) => {
                self.scan_result.scan_status = ScanStatus::Timeout;
            },
        }
        self.scan_result.scan_time = Instant::now().duration_since(start_time);
    }
    /// Return scan result.
    pub fn get_result(&mut self) -> DomainScanResult{
        return self.scan_result.clone();
    }
    /// Run scan and return result
    pub async fn scan(&mut self) -> DomainScanResult {
        self.run_scan().await;
        self.scan_result.clone()
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<String>>> {
        self.rx.clone()
    }
}

async fn scan_domain(_base_domain: String, _word_list: Vec<String>, _ptx: &Arc<Mutex<Sender<String>>>) -> Vec<Domain> {
    let result: Vec<Domain> = vec![];
    result
}

async fn scan_domain_passive(_base_domain: String, _ptx: &Arc<Mutex<Sender<String>>>) -> Vec<Domain>  {
    let result: Vec<Domain> = vec![];
    //"https://crt.sh/?dNSName=example.com&output=json"
/*     let url = match Url::parse_with_params(URL_CRT, &[("dNSName", base_domain.as_str()), ("output", "json")]){
        Ok(url) => url,
        Err(e) => {
            println!("{}",e);
            return result;
        },
    }; */
    result
}
