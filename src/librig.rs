mod dns;

pub fn do_lookup(domain: String) {
    let mut query = dns::Query::new(domain, dns::RecordType::A, dns::RecordClass::IN);

    query.dump_query();
}
