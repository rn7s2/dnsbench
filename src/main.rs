use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::{SocketAddr, UdpSocket},
    sync::{mpsc::channel, Arc, Mutex},
};

use addr::parse_domain_name;
use clap::Parser;
use dns_parser::QueryClass;
use dns_parser::QueryType;
use rand::seq::SliceRandom;

fn main() {
    let args = Args::parse();

    let domains = Arc::new(read_domains(&args.domains));

    let (tx, rx) = channel();
    let mut threads = Vec::new();

    let id = Arc::new(Mutex::new(0u16));
    for _ in 0..args.threads {
        let tx = tx.clone();
        let server = args.server;
        let number = args.number;
        let id = id.clone();
        let domains = domains.clone();
        let query_type = match args.record.as_str() {
            "A" => QueryType::A,
            "AAAA" => QueryType::AAAA,
            _ => panic!("Invalid query type"),
        };
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        threads.push(std::thread::spawn(move || {
            let mut rng = rand::thread_rng();
            for _ in 0..number {
                let mut id = id.lock().unwrap();
                let rid = *id;
                *id += 1;
                drop(id);

                let qname = domains.choose(&mut rng).unwrap();
                let status = send_req(&socket, &server, rid, qname, query_type);
                tx.send(status.clone()).unwrap();
                if status == WorkerStatus::Sent {
                    let status = recv_resp(&socket, &server, rid, args.timeout);
                    tx.send(status).unwrap();
                }
            }
            tx.send(WorkerStatus::AllFinished).unwrap();
        }));
    }

    let mut sent = 0;
    let mut success = 0;
    let mut timeout = 0;
    let mut failed = 0;
    let mut all_finished = 0;
    loop {
        match rx.recv().unwrap() {
            WorkerStatus::Sent => sent += 1,
            WorkerStatus::Success => success += 1,
            WorkerStatus::Timeout => timeout += 1,
            WorkerStatus::Failed => failed += 1,
            WorkerStatus::AllFinished => all_finished += 1,
        }
        println!(
            "sent: {}, success: {}, timeout: {}, failed: {}, thread finished: {}",
            sent, success, timeout, failed, all_finished
        );
        if all_finished == args.threads {
            break;
        }
    }
}

#[derive(Parser, Debug)]
struct Args {
    /// Number of threads
    #[clap(short = 'p', long, default_value = "10")]
    threads: u32,

    /// Max request number for each thread
    #[clap(short, long, default_value = "100")]
    number: u32,

    /// Domains file, from which the domains are randomly selected to send query
    #[clap(short, long, default_value = "domains.txt")]
    domains: String,

    /// Query A or AAAA record
    #[clap(short, long, default_value = "A")]
    record: String,

    /// DNS server address
    #[clap(short, long, default_value = "127.0.0.1:53")]
    server: SocketAddr,

    /// Timeout for each request (ms)
    #[clap(short, long, default_value = "20")]
    timeout: u32,
}

#[derive(Clone, Debug, PartialEq)]
enum WorkerStatus {
    Sent,
    Success,
    Timeout,
    Failed,
    AllFinished,
}

fn send_req(
    socket: &UdpSocket,
    server: &SocketAddr,
    id: u16,
    domain: &str,
    query_type: QueryType,
) -> WorkerStatus {
    let mut builder = dns_parser::Builder::new_query(id, true);
    builder.add_question(domain, true, query_type, QueryClass::IN);
    let packet = builder.build().unwrap();

    match socket.send_to(&packet, server) {
        Ok(_) => WorkerStatus::Sent,
        Err(_) => WorkerStatus::Failed,
    }
}

fn recv_resp(socket: &UdpSocket, server: &SocketAddr, id: u16, timeout: u32) -> WorkerStatus {
    let mut packet = Vec::new();
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(timeout.into())))
        .unwrap();
    match socket.recv_from(&mut packet) {
        Ok(_) => (),
        Err(e) => {
            return match e.kind() {
                std::io::ErrorKind::TimedOut => WorkerStatus::Timeout,
                _ => WorkerStatus::Failed,
            }
        }
    };

    match dns_parser::Packet::parse(&packet) {
        Ok(v) => {
            if v.header.id == id {
                WorkerStatus::Success
            } else {
                recv_resp(socket, server, id, timeout)
            }
        }
        Err(_) => WorkerStatus::Failed,
    }
}

fn read_domains(file: &str) -> Vec<String> {
    let mut rd = BufReader::new(File::open(file).unwrap());
    let mut domains = Vec::new();
    loop {
        let mut line = String::new();
        match rd.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let domain = line.to_string();
                if let Ok(_) = parse_domain_name(&domain) {
                    domains.push(domain);
                }
            }
            Err(_) => break,
        }
    }
    domains
}
