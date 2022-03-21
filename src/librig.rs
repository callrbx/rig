use dns::Answer;
use std::net::Ipv4Addr;

mod dns;

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

pub fn do_lookup(hostname: String, server: Option<String>) {
    let response = match server {
        Some(server) => {
            dns::Query::do_query_server(hostname, server, dns::RecordType::A, dns::RecordClass::IN)
        }
        None => dns::Query::do_query(hostname, dns::RecordType::A, dns::RecordClass::IN),
    };

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
