use dns::Answer;
use std::{
    fs::File,
    io::{self, BufRead},
    net::Ipv4Addr,
    path::Path,
};

mod dns;

const RESOLVCONF: &str = "/etc/resolv.conf";

fn display_answer(r: Answer) {
    match r.len {
        4 => {
            println!(
                "{:16} {} {} {}",
                Ipv4Addr::new(r.data[0], r.data[1], r.data[2], r.data[3]),
                r.ttl,
                r.rclass.get_str(),
                r.rtype.get_str()
            )
        }
        _ => {}
    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn parse_resolvconf_nameserver(conf: Option<String>) -> String {
    let config_file = match conf {
        Some(c) => c,
        None => RESOLVCONF.to_string(),
    };

    if let Ok(lines) = read_lines(config_file) {
        // Consumes the iterator, returns an (Optional) String
        for line in lines {
            if let Ok(data) = line {
                if data.starts_with("nameserver") {
                    let nameserver = data
                        .split_ascii_whitespace()
                        .next_back()
                        .unwrap_or("127.0.0.1")
                        .to_string();
                    return nameserver;
                }
            }
        }
    }

    return String::from("127.0.0.1");
}

pub fn do_lookup(hostname: String, nameserver: String) {
    let response = dns::Query::do_query(
        hostname,
        nameserver.to_string(),
        dns::RecordType::A,
        dns::RecordClass::IN,
    );

    match response {
        Some(r) => {
            println!("{}", r.question.get_name_str());
            for a in r.answer {
                display_answer(a);
            }
        }
        None => {
            eprintln!("DNS Lookup failed");
        }
    }
}
