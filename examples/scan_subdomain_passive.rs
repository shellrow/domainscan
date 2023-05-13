use domainscan::scanner::DomainScanner;
use domainscan::result::ScanStatus;
use tokio::runtime::Runtime;
use std::time::Duration;
use std::thread;

fn main() {
    let mut domain_scanner = match DomainScanner::new(){
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    domain_scanner.set_passive(true);
    let apex_domain = String::from("google.com");
    domain_scanner.set_base_domain(apex_domain);
    domain_scanner.set_timeout(Duration::from_millis(30000));
    let rx = domain_scanner.get_progress_receiver();
    let rt = Runtime::new().unwrap();
    // Run scan 
    let handle = thread::spawn(move|| {
        rt.block_on(async {
            domain_scanner.scan().await
        })
    });
    // Print progress
    while let Ok(_domain) = rx.lock().unwrap().recv() {
        //println!("Debug: {}", domain);
    }
    let result = handle.join().unwrap();
    print!("Status: ");
    match result.scan_status {
        ScanStatus::Done => {println!("Done")},
        ScanStatus::Timeout => {println!("Timed out")},
        _ => {println!("Error")},
    }
    println!("Domain Scan Result:");
    for domain in result.domains {
        println!("{}", domain.domain_name);
        for ip in domain.ips{
            println!("    {}", ip);
        }
    }
    println!("Scan Time: {:?}", result.scan_time);
}
