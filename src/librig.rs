mod dns;

pub fn do_lookup(hostname: String) {
    let response = match dns::Query::do_query(hostname, dns::RecordType::A, dns::RecordClass::IN) {
        Some(r) => r,
        None => {
            eprintln!("Query Failed");
            std::process::exit(1);
        }
    };

    println!("{:?}", response)
}
