use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::{SocketAddr, UdpSocket},
    sync::{mpsc::channel, Arc, Mutex},
    thread::{self, ThreadId},
    time::SystemTime,
};

use addr::parse_domain_name;
use clap::Parser;
use dns_parser::{QueryClass, QueryType};
use rand::seq::SliceRandom;

fn main() {
    let args = Args::parse();

    let domains = Arc::new(read_domains(&args.domains));

    let (tx, rx) = channel();
    let mut threads = Vec::new();

    let now = SystemTime::now();

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
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.connect(server).unwrap();
        threads.push(std::thread::spawn(move || {
            let mut rng = rand::thread_rng();
            for _ in 0..number {
                let mut id = id.lock().unwrap();
                let rid = *id;
                *id += 1;
                drop(id);

                let qname = domains.choose(&mut rng).unwrap();
                if args.debug >= 2 {
                    println!("select domain: {}", qname);
                }
                let (status, tid) = send_req(&socket, rid, qname, query_type);
                tx.send((status.clone(), tid)).unwrap();
                if status == WorkerStatus::Sent {
                    let (status, tid) = recv_resp(&socket, rid, args.timeout, args.debug);
                    tx.send((status, tid)).unwrap();
                }
            }
            tx.send((WorkerStatus::AllFinished, thread::current().id()))
                .unwrap();
        }));
    }

    let mut sent = 0;
    let mut success = 0;
    let mut timeout = 0;
    let mut failed = 0;
    let mut all_finished = 0;
    loop {
        let (status, tid) = rx.recv().unwrap();
        match status {
            WorkerStatus::Sent => sent += 1,
            WorkerStatus::Success => success += 1,
            WorkerStatus::Timeout => timeout += 1,
            WorkerStatus::Failed => failed += 1,
            WorkerStatus::AllFinished => all_finished += 1,
        }
        let percent = (100.0 * sent as f64 / (args.threads * args.number) as f64) as u32;
        if args.debug >= 1 {
            println!(
                "{:?} sent: {}, success: {}, timeout: {}, failed: {}, thread finished: {}, percent: {}%, time: {}s",
                tid, sent, success, timeout, failed, all_finished, percent,now.elapsed().unwrap().as_secs_f32()
            );
        }
        if all_finished == args.threads {
            break;
        }
    }

    println!(
        "ALLDONE sent: {}, success: {}, timeout: {}, failed: {}, thread finished: {}, percent: 100%, time: {}s",
        sent,
        success,
        timeout,
        failed,
        all_finished,
        now.elapsed().unwrap().as_secs_f32()
    );
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
    #[clap(short, long)]
    server: SocketAddr,

    /// Timeout for each request (ms)
    #[clap(short, long, default_value = "500")]
    timeout: u64,

    /// Debug level, 0: no debug, 1: print debug info, 2: print all info
    #[clap(short = 'v', long, default_value = "0")]
    debug: u32,
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
    id: u16,
    domain: &str,
    query_type: QueryType,
) -> (WorkerStatus, ThreadId) {
    let mut builder = dns_parser::Builder::new_query(id, true);
    builder.add_question(domain, true, query_type, QueryClass::IN);
    let mut packet = builder.build().unwrap();
    let len = packet.len();
    packet[len - 2] = 0; // fix dns_parser bug (unclear why)

    (
        match socket.send(&packet) {
            Ok(_) => WorkerStatus::Sent,
            Err(_) => WorkerStatus::Failed,
        },
        thread::current().id(),
    )
}

fn recv_resp(socket: &UdpSocket, id: u16, timeout: u64, debug: u32) -> (WorkerStatus, ThreadId) {
    let mut packet = [0; 4096];
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(timeout)))
        .unwrap();
    match socket.recv(&mut packet) {
        Ok(_) => (),
        Err(e) => {
            return (
                match e.kind() {
                    std::io::ErrorKind::TimedOut => WorkerStatus::Timeout,
                    _ => WorkerStatus::Failed,
                },
                thread::current().id(),
            );
        }
    };

    match dns_parser::Packet::parse(&packet) {
        Ok(v) => {
            if v.header.id == id {
                if debug >= 2 {
                    println!("OK, {} -> {:?}", v.questions[0].qname, v.answers);
                }
                (WorkerStatus::Success, thread::current().id())
            } else {
                recv_resp(socket, id, timeout, debug)
            }
        }
        Err(_) => (WorkerStatus::Failed, thread::current().id()),
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
