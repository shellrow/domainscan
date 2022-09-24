use std::net::IpAddr;
use std::time::{Duration, Instant};
use std::sync::{Mutex, Arc};
use std::sync::mpsc::{channel ,Sender, Receiver};
use futures::{stream, StreamExt};
use tokio::time::{timeout};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use reqwest::Url;
use crate::model::{Domain, ScanStatus, DomainScanResult, CertEntry};
use crate::config::{URL_CRT, DEFAULT_USER_AGENT};

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
            timeout(self.timeout, scan_subdomain_passive(self.base_domain.clone(), &self.tx)).await
        }else{
            timeout(self.timeout, scan_subdomain(self.base_domain.clone(), self.word_list.clone(), &self.tx)).await
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

async fn resolve_domain(domain: String) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = vec![];
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    match resolver.lookup_ip(domain) {
        Ok(lip) => {
            for ip in lip.iter() {
                ips.push(ip);
            }
        },
        Err(_) => {},
    }
    ips
}

fn extract_domain(target: String) -> String {
    let mut domain_name: String = target;
    match domain_name.strip_prefix("*.") {
        Some(d) => {
            domain_name = d.to_string();
        },
        None => {},
    }
    domain_name
}

fn is_subdomain(domain: String, apex_domain: String) -> bool {
    domain.contains(&apex_domain) && domain.len() > apex_domain.len()
}

async fn scan_subdomain(base_domain: String, word_list: Vec<String>, ptx: &Arc<Mutex<Sender<String>>>) -> Vec<Domain> {
    let mut result: Vec<Domain> = vec![];
    let scan_results: Arc<Mutex<Vec<Domain>>> = Arc::new(Mutex::new(vec![]));
    let mut target_domains: Vec<String> = vec![];
    for word in word_list {
        target_domains.push(format!("{}.{}", word, base_domain));
    }
    let r = stream::iter(target_domains).map(|domain| {
        async move {
            let ips: Vec<IpAddr> = resolve_domain(domain.clone()).await;
            let d = Domain {
                domain_name: domain.clone(),
                ips: ips,
            };
            match ptx.lock() {
                Ok(lr) => {
                    match lr.send(domain) {
                        Ok(_) => {},
                        Err(_) => {},
                    }
                },
                Err(_) => {},
            }
            d
        }
    }).buffer_unordered(100);
    r.for_each(|domain| async {
        if domain.ips.len() > 0 {
            scan_results.lock().unwrap().push(domain);
        }
    }).await;
    for domain in scan_results.lock().unwrap().iter() {
        result.push(domain.to_owned());
    }
    result
}

async fn scan_subdomain_passive(base_domain: String, _ptx: &Arc<Mutex<Sender<String>>>) -> Vec<Domain>  {
    let mut result: Vec<Domain> = vec![];
    let mut certs: Vec<CertEntry> = vec![];
    //"https://crt.sh/?dNSName=example.com&output=json"
    let url = match Url::parse_with_params(URL_CRT, &[("dNSName", base_domain.clone().as_str()), ("output", "json")]){
        Ok(url) => url,
        Err(e) => {
            println!("{}",e);
            return result;
        },
    };
    let client = reqwest::Client::builder().timeout(Duration::from_secs(60)).build().expect("failed to build HTTP reqest client");
    let res = client.get(url).header(reqwest::header::USER_AGENT, DEFAULT_USER_AGENT).send().await;
    match res {
        Ok(r) => {
            if r.status().is_success() {
                match r.text().await {
                    Ok(res_text) => {
                        let certs_json:serde_json::Value = serde_json::from_str(res_text.as_str()).unwrap();
                        if certs_json.is_array() {
                            let cert_array = certs_json.as_array().unwrap();
                            for cert in cert_array {
                                match serde_json::to_string(cert) {
                                    Ok(cert) => {
                                        let cert:CertEntry = match serde_json::from_str(cert.as_str()){
                                            Ok(cert) => cert,
                                            Err(_) => continue,
                                        };
                                        certs.push(cert);
                                    },
                                    Err(_) => {},
                                }
                            }
                        }
                    },
                    Err(_) => {},
                };
            }
        },
        Err(_) => {},
    }
    for cert in certs {
        let domain_name: String = extract_domain(cert.common_name);
        if is_subdomain(domain_name.clone(), base_domain.clone()) {
            let ips: Vec<IpAddr> = resolve_domain(domain_name.clone()).await;
            if ips.len() > 0 {
                let domain = Domain {
                    domain_name: domain_name,
                    ips: ips,
                };
                result.push(domain);
            }
        }
    }
    result
}
