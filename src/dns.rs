use std::io::{BufWriter, Write};

use bincode::Options;
use bitfield::bitfield;
use serde::{Deserialize, Serialize};

// TYPE fields are used in resource records - RFC 1035 3.2.2
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
pub enum RecordType {
    A = 1, // 1 a host address
    NS,    // 2 an authoritative name server
    MD,    // 3 a mail destination (Obsolete - use MX)
    MF,    // 4 a mail forwarder (Obsolete - use MX)
    CNAME, // 5 the canonical name for an alias
    SOA,   // 6 marks the start of a zone of authority
    MB,    // 7 a mailbox hostname name (EXPERIMENTAL)
    MG,    // 8 a mail group member (EXPERIMENTAL)
    MR,    // 9 a mail rename hostname name (EXPERIMENTAL)
    NULL,  // 10 a null RR (EXPERIMENTAL)
    WKS,   // 11 a well known service description
    PTR,   // 12 a hostname name pointer
    HINFO, // 13 host information
    MINFO, // 14 mailbox or mail list information
    MX,    // 15 mail exchange
    TXT,   // 16 text strings
}

// CLASS fields appear in resource records - RFC 1035 3.2.4
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
pub enum RecordClass {
    IN = 1, // 1 the Internet
    CS,     // 2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH,     // 3 the CHAOS class
    HS,     // 4 Hesiod [Dyer 87]
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum Class {}

// Header Flags bitfield
bitfield! {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct HeaderFlags(MSB0 [u16]);
    u8;
    qr, set_qr: 0;
    opcode, set_opcode: 4, 1;
    aa, _: 5;
    tc, _: 6;
    rd, set_rd: 7;
    ra, _: 8;
    z, _: 9;
    ad, set_ad: 10;
    auth, _: 11;
    rcode, _: 15, 12;
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Header {
    id: u16,
    flags: HeaderFlags<[u16; 1]>,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

impl Header {
    fn new(id: Option<u16>) -> Self {
        Self {
            id: match id {
                Some(n) => n,
                None => rand::random(),
            },
            flags: HeaderFlags([0]),
            qd_count: 1, // This is basically defacto; BIND servers reject QD_COUNT != 1
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Question {
    name: Vec<u8>,
    rtype: RecordType,
    rclass: RecordClass,
}

impl Question {
    fn generate_label(hostname: String) -> Vec<u8> {
        let mut label: Vec<u8> = Vec::new();

        // Label consists of len field, followed by chunk
        for chunk in hostname.split(".") {
            let l = chunk.len();
            label.push(l as u8);
            label.extend(chunk.as_bytes());
        }

        label.push(0 as u8); // trailing null byte

        return label;
    }

    fn new(hostname: String, rtype: RecordType, rclass: RecordClass) -> Self {
        Self {
            name: Self::generate_label(hostname),
            rtype: rtype, // hard code A for now
            rclass: rclass,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Answer {
    name: Vec<u8>,
    rtype: RecordType,
    rclass: RecordClass,
    ttl: u32,
    len: u16,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Query {
    header: Header,
    question: Question,
}

impl Query {
    pub fn new(hostname: String, rtype: RecordType, rclass: RecordClass) -> Self {
        let mut query = Query {
            header: Header::new(None),
            question: Question::new(hostname, rtype, rclass),
        };

        // enable "standard query" bits
        query.header.flags.set_rd(true);
        query.header.flags.set_ad(true);

        return query;
    }

    fn query_serialize(&mut self) -> Vec<u8> {
        let mut ser_query: Vec<u8> = Vec::new();

        match bincode::DefaultOptions::new()
            .with_big_endian()
            .with_fixint_encoding()
            .serialize(&self.header)
        {
            Ok(mut v) => ser_query.append(&mut v),
            Err(e) => {
                eprintln!("Failed to serialize query header: {}", e);
                std::process::exit(1);
            }
        };

        ser_query.append(&mut self.question.name);

        match bincode::DefaultOptions::new()
            .with_big_endian()
            .with_fixint_encoding()
            .serialize(&(self.question.rtype as u16))
        {
            Ok(mut v) => ser_query.append(&mut v),
            Err(e) => {
                eprintln!("Failed to serialize query question type: {}", e);
                std::process::exit(1);
            }
        };

        match bincode::DefaultOptions::new()
            .with_big_endian()
            .with_fixint_encoding()
            .serialize(&(self.question.rclass as u16))
        {
            Ok(mut v) => ser_query.append(&mut v),
            Err(e) => {
                eprintln!("Failed to serialize query question class: {}", e);
                std::process::exit(1);
            }
        };

        return ser_query;
    }

    pub fn dump_query(&mut self) {
        let encoded = self.query_serialize();

        let mut writer = BufWriter::new(std::io::stdout());

        writer.write(&encoded).unwrap();
        writer.flush().unwrap();
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Response {
    header: Header,
    answer: Vec<Answer>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_flags() {
        let a1 = [5, 57, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]; // not query
        let a2 = [5, 57, 1, 32, 0, 1, 0, 0, 0, 0, 0, 0]; // query set

        let mut header = Header::new(Some(1337));

        let encoded = bincode::DefaultOptions::new()
            .with_big_endian()
            .with_fixint_encoding()
            .serialize(&header)
            .unwrap();

        assert!(encoded == a1);

        header.flags.set_rd(true);
        header.flags.set_ad(true);

        let encoded = bincode::DefaultOptions::new()
            .with_big_endian()
            .with_fixint_encoding()
            .serialize(&header)
            .unwrap();

        assert!(encoded == a2);
        assert!(header.flags.0 == [0x0120]); // "standard" dns query flags
    }

    #[test]
    fn test_label_gen() {
        let l1 = [
            6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];
        let l2 = [
            5, 0x67, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];

        assert!(Question::generate_label(String::from("google.com")) == l1);
        assert!(Question::generate_label(String::from("gogle.com")) == l2);
    }

    #[test]
    fn test_a_in_gen() {
        let expected = [
            5, 57, 1, 32, 0, 1, 0, 0, 0, 0, 0, 0, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109,
            0, 0, 1, 0, 1,
        ];

        let hostname = String::from("google.com");
        let rtype = RecordType::A;
        let rclass = RecordClass::IN;

        let mut q = Query::new(hostname, rtype, rclass);

        // ignore the randomized ID
        assert!(q.query_serialize()[2..] == expected[2..]);
    }
}
