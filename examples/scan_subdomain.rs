use domainscan::result::ScanStatus;
use domainscan::scanner::DomainScanner;
use tokio::runtime::Runtime;
//use std::fs::read_to_string;
use std::thread;
use std::time::Duration;

fn main() {
    let mut domain_scanner = match DomainScanner::new() {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let apex_domain = String::from("google.com");
    domain_scanner.set_base_domain(apex_domain);
    /* let data = read_to_string("namelist.txt");
    let text = match data {
        Ok(content) => content,
        Err(e) => {panic!("Could not open or find file: {}", e);}
    };
    let word_list: Vec<&str> = text.trim().split("\n").collect();
    domain_scanner.set_word_list(word_list); */
    // TOP20
    domain_scanner.set_word_list(vec![
        "www",
        "mail",
        "ftp",
        "localhost",
        "webmail",
        "smtp",
        "webdisk",
        "pop",
        "cpanel",
        "whm",
        "ns1",
        "ns2",
        "autodiscover",
        "autoconfig",
        "ns",
        "test",
        "m",
        "blog",
        "dev",
        "www2",
    ]);
    domain_scanner.set_timeout(Duration::from_millis(10000));
    let rx = domain_scanner.get_progress_receiver();
    let rt = Runtime::new().unwrap();
    // Run scan
    let handle = thread::spawn(move || rt.block_on(async { domain_scanner.scan().await }));
    // Print progress
    while let Ok(_domain) = rx.lock().unwrap().recv() {
        //println!("Debug: {}", domain);
    }
    let result = handle.join().unwrap();
    print!("Status: ");
    match result.scan_status {
        ScanStatus::Done => {
            println!("Done")
        }
        ScanStatus::Timeout => {
            println!("Timed out")
        }
        _ => {
            println!("Error")
        }
    }
    println!("Domain Scan Result:");
    for domain in result.domains {
        println!("{}", domain.domain_name);
        for ip in domain.ips {
            println!("    {}", ip);
        }
    }
    println!("Scan Time: {:?}", result.scan_time);
}
