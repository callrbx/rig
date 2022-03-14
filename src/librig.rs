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

pub fn do_lookup(hostname: String) {
    let response = match dns::Query::do_query(hostname, dns::RecordType::A, dns::RecordClass::IN) {
        Some(r) => r,
        None => {
            eprintln!("Query Failed");
            std::process::exit(1);
        }
    };

    println!("{}", response.question.get_name_str());
    for a in response.answer {
        display_answer(a);
    }
}
