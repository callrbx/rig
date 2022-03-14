use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;
use std::net::UdpSocket;

use bincode::Options;
use bitfield::bitfield;
use serde::{Deserialize, Serialize};

const ADDR: &str = "1.1.1.1:53";
const BUF_SIZE: usize = 1024;
const HDR_SIZE: usize = 12;
const RESP_DATA_SIZE: usize = 12;

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

impl RecordType {
    fn from_u16(value: u16) -> RecordType {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            3 => RecordType::MD,
            4 => RecordType::MF,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            7 => RecordType::MB,
            8 => RecordType::MG,
            9 => RecordType::MR,
            10 => RecordType::NULL,
            11 => RecordType::WKS,
            12 => RecordType::PTR,
            13 => RecordType::HINFO,
            14 => RecordType::MINFO,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            _ => {
                eprintln!("Invalid Type: {}", value);
                std::process::exit(1);
            }
        }
    }

    pub fn get_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::NS => "NS",
            RecordType::MD => "MD",
            RecordType::MF => "MF",
            RecordType::CNAME => "CNAME",
            RecordType::SOA => "SOA",
            RecordType::MB => "MB",
            RecordType::MG => "MG",
            RecordType::MR => "MR",
            RecordType::NULL => "NULL",
            RecordType::WKS => "WKS",
            RecordType::PTR => "PTW",
            RecordType::HINFO => "HINFO",
            RecordType::MINFO => "MINFO",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
        }
    }
}

// CLASS fields appear in resource records - RFC 1035 3.2.4
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
pub enum RecordClass {
    IN = 1, // 1 the Internet
    CS,     // 2 the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH,     // 3 the CHAOS class
    HS,     // 4 Hesiod [Dyer 87]
}

impl RecordClass {
    fn from_u16(value: u16) -> RecordClass {
        match value {
            1 => RecordClass::IN,
            2 => RecordClass::CS,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            _ => {
                eprintln!("Invalid Class: {}", value);
                std::process::exit(1);
            }
        }
    }

    pub fn get_str(&self) -> &'static str {
        match self {
            RecordClass::IN => "IN",
            RecordClass::CS => "CS",
            RecordClass::CH => "CH",
            RecordClass::HS => "HS",
        }
    }
}

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
pub struct Header {
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

fn get_name(bytes: &Vec<u8>) -> (String, usize) {
    let mut ptr = 0;
    let mut label: Vec<u8> = Vec::new();
    loop {
        let t = bytes[ptr];
        if t == 0 {
            break;
        }
        if !t.is_ascii_alphanumeric() {
            label.extend(&bytes[(ptr + 1)..((t as usize) + ptr + 1)]);
            label.push('.' as u8);
        }
        ptr += t as usize + 1;
    }

    let name = String::from_utf8(label).expect("Failed to parse name");

    return (name, ptr + 1);
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Question {
    name: Vec<u8>,
    rtype: RecordType,
    rclass: RecordClass,
}

impl Question {
    pub fn get_name_str(&self) -> String {
        let (name, _) = get_name(&self.name);

        return name;
    }

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

    fn from_bytes(bytes: Vec<u8>) -> (Self, usize) {
        let (_, mut ptr) = get_name(&bytes);

        let mut cur = Cursor::new(bytes[ptr..].to_vec());

        let rtype =
            RecordType::from_u16(cur.read_u16::<BigEndian>().expect("failed to parse type"));
        let rclass =
            RecordClass::from_u16(cur.read_u16::<BigEndian>().expect("failed to parse class"));

        let question = Self {
            name: bytes[..ptr].to_vec(),
            rtype: rtype,
            rclass: rclass,
        };

        ptr += 4; //advance remaining bytes past question

        return (question, ptr);
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
    pub domain: u16,
    pub rtype: RecordType,
    pub rclass: RecordClass,
    pub ttl: u32,
    pub len: u16,
    pub data: Vec<u8>,
}

impl Answer {
    fn from_bytes(bytes: Vec<u8>) -> (Self, usize) {
        let mut ptr = 0;

        let mut cur = Cursor::new(&bytes);

        let domain = cur.read_u16::<BigEndian>().expect("failed to parse domain");
        let rtype =
            RecordType::from_u16(cur.read_u16::<BigEndian>().expect("failed to parse type"));
        let rclass =
            RecordClass::from_u16(cur.read_u16::<BigEndian>().expect("failed to parse class"));
        let ttl = cur.read_u32::<BigEndian>().expect("failed to parse ttl");
        let data_len = cur
            .read_u16::<BigEndian>()
            .expect("failed to parse data len");

        let data: Vec<u8> =
            bytes[cur.position() as usize..cur.position() as usize + data_len as usize].to_vec();

        let ans = Answer {
            domain: domain,
            rtype: rtype,
            rclass: rclass,
            ttl: ttl,
            len: data_len,
            data: data,
        };

        ptr += RESP_DATA_SIZE + data_len as usize;

        return (ans, ptr);
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Query {
    header: Header,
    question: Question,
}

impl Query {
    pub fn do_query(hostname: String, rtype: RecordType, rclass: RecordClass) -> Option<Response> {
        let mut query = Self::new(hostname, rtype, rclass);

        let response = match query.send_query(ADDR.to_string()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Query failed: {}", e);
                return None;
            }
        };

        return Some(response);
    }

    fn new(hostname: String, rtype: RecordType, rclass: RecordClass) -> Self {
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

    fn send_query(&mut self, addr: String) -> std::io::Result<Response> {
        let packet_bytes = self.query_serialize();

        let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind to address");

        socket
            .send_to(&packet_bytes, addr)
            .expect("Failed to connect to DNS server");

        let mut buf = [0; BUF_SIZE];
        let mut rvec: Vec<u8> = Vec::new();
        match socket.recv(&mut buf) {
            Ok(size) => rvec.extend(&buf[..size]),
            Err(e) => println!("recv function failed: {:?}", e),
        }

        let resp = Response::from_bytes(rvec);
        return Ok(resp);
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Response {
    pub header: Header,
    pub question: Question,
    pub answer: Vec<Answer>,
}

impl Response {
    fn from_bytes(bytes: Vec<u8>) -> Self {
        if bytes.len() < HDR_SIZE {
            eprintln!("Failed to deserialize header; only {} bytes", bytes.len());
            std::process::exit(1);
        }

        let header: Header = bincode::DefaultOptions::new()
            .with_big_endian()
            .with_fixint_encoding()
            .deserialize(&bytes[..HDR_SIZE])
            .unwrap();

        let mut _ptr = HDR_SIZE;

        let (question, ptr) = Question::from_bytes(bytes[HDR_SIZE..].to_vec());
        _ptr += ptr;

        let mut answers: Vec<Answer> = Vec::new();

        for _ in 0..header.an_count {
            let (answer, ptr) = Answer::from_bytes(bytes[_ptr..].to_vec());
            _ptr += ptr;
            answers.push(answer);
        }

        let resp = Response {
            header: header,
            question: question,
            answer: answers,
        };

        return resp;
    }
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

    #[test]
    fn test_record_type_convert() {
        assert!(RecordType::from_u16(1) == RecordType::A);
        assert!(RecordType::from_u16(2) == RecordType::NS);
        assert!(RecordType::from_u16(3) == RecordType::MD);
        assert!(RecordType::from_u16(4) == RecordType::MF);
        assert!(RecordType::from_u16(5) == RecordType::CNAME);
        assert!(RecordType::from_u16(6) == RecordType::SOA);
        assert!(RecordType::from_u16(7) == RecordType::MB);
        assert!(RecordType::from_u16(8) == RecordType::MG);
        assert!(RecordType::from_u16(9) == RecordType::MR);
        assert!(RecordType::from_u16(10) == RecordType::NULL);
        assert!(RecordType::from_u16(11) == RecordType::WKS);
        assert!(RecordType::from_u16(12) == RecordType::PTR);
        assert!(RecordType::from_u16(13) == RecordType::HINFO);
        assert!(RecordType::from_u16(14) == RecordType::MINFO);
        assert!(RecordType::from_u16(15) == RecordType::MX);
        assert!(RecordType::from_u16(16) == RecordType::TXT);
    }

    #[test]
    fn test_record_class_convert() {
        assert!(RecordClass::from_u16(1) == RecordClass::IN);
        assert!(RecordClass::from_u16(2) == RecordClass::CS);
        assert!(RecordClass::from_u16(3) == RecordClass::CH);
        assert!(RecordClass::from_u16(4) == RecordClass::HS);
    }

    #[test]
    fn test_get_name() {
        let bytes: Vec<u8> = vec![6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0];

        assert!(get_name(&bytes) == (String::from("google.com."), 12));
    }

    #[test]
    fn test_gen_label() {
        let bytes: Vec<u8> = vec![6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0];

        assert!(Question::generate_label("google.com".to_string()) == bytes);
    }
}
