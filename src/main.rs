//! ntpqte — the constellation's clock CLI.
//!
//!   ntpqte --server time.apple.com            one query, the council line
//!   ntpqte --consensus s1 s2 s3               the median over the elders
//!   ntpqte --journal --server time.apple.com  append one drift row

use std::env;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let server = flag(&args, "--server").unwrap_or_else(|| "time.apple.com".to_string());
    let timeout = flag(&args, "--timeout").and_then(|s| s.parse().ok()).unwrap_or(4.0);

    match args.iter().position(|a| a == "--consensus") {
        Some(i) => {
            let peers: Vec<&String> = args[i + 1..].iter().collect();
            if peers.is_empty() {
                eprintln!("--consensus needs at least one server");
                return ExitCode::from(2);
            }
            let mut offsets = Vec::new();
            for p in &peers {
                match ntpqte::query(p, 123, Duration::from_secs_f64(timeout)) {
                    Ok((o, _d)) => {
                        println!("  {p}: {o:+.2} ms");
                        offsets.push(o);
                    }
                    Err(e) => println!("  {p}: {e}"),
                }
            }
            let mean = ntpqte::consensus_ms(&offsets);
            println!("council consensus: {mean:+.2} ms (median over {} elders)", offsets.len());
        }
        None => {
            match ntpqte::query(&server, 123, Duration::from_secs_f64(timeout)) {
                Ok((off, delay)) => {
                    println!("{off:+.3} +/- {delay:.3} ms  {server}");
                    if args.iter().any(|a| a == "--journal") {
                        let home = env::var("HOME").unwrap_or_else(|_| ".".into());
                        let journal = format!("{home}/.ntpqte/journal.jsonl");
                        match ntpqte::journal_row(std::path::Path::new(&journal), &server, off, delay) {
                            Ok(()) => println!("journal → {journal}"),
                            Err(e) => eprintln!("journal: {e}"),
                        }
                    }
                }
                Err(e) => {
                    eprintln!("query {server}: {e}");
                    return ExitCode::from(1);
                }
            }
        }
    }

    #[allow(clippy::let_and_return)]
    ExitCode::SUCCESS
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}