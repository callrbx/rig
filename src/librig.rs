mod dns;

pub fn do_lookup(hostname: String) {
    let mut query = dns::Query::new(hostname, dns::RecordType::A, dns::RecordClass::IN);

    query.dump_query();
}
