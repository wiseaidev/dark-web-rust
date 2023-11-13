use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};

const ICMP_TYPE_CODE_MAP: &[((u8, u8), &str)] = &[
    ((0, 0), "Echo Reply"),
    ((3, 0), "Destination Unreachable - Net is unreachable"),
    ((3, 1), "Destination Unreachable - Host is unreachable"),
    ((3, 2), "Destination Unreachable - Protocol is unreachable"),
    ((3, 3), "Destination Unreachable - Port is unreachable"),
    ((3, 4), "Destination Unreachable - Fragmentation is needed and Don't Fragment was set"),
    ((3, 5), "Destination Unreachable - Source route failed"),
    ((3, 6), "Destination Unreachable - Destination network is unknown"),
    ((3, 7), "Destination Unreachable - Destination host is unknown"),
    ((3, 8), "Destination Unreachable - Source host is isolated"),
    ((3, 9), "Destination Unreachable - Communication with destination network is administratively prohibited"),
    ((3, 10), "Destination Unreachable - Communication with destination host is administratively prohibited"),
    ((3, 11), "Destination Unreachable - Destination network is unreachable for type of service"),
    ((3, 12), "Destination Unreachable - Destination host is unreachable for type of service"),
    ((3, 13), "Destination Unreachable - Communication is administratively prohibited"),
    ((3, 14), "Destination Unreachable - Host precedence violation"),
    ((3, 15), "Destination Unreachable - Precedence cutoff is in effect"),
    ((4, 0), "Source Quench"),
    ((5, 0), "Redirect"),
    ((8, 0), "Echo"),
    ((9, 0), "Router Advertisement"),
    ((10, 0), "Router Selection"),
    ((11, 0), "Time Exceeded"),
    ((12, 0), "Parameter Problem"),
    ((13, 0), "Timestamp"),
    ((14, 0), "Timestamp Reply"),
    ((15, 0), "Information Request"),
    ((16, 0), "Information Reply"),
    ((17, 0), "Address Mask Request"),
    ((18, 0), "Address Mask Reply"),
    ((30, 0), "Traceroute"),
    ((40, 0), "Photuris"),
    ((41, 0), "ICMP for IPv6"),
    ((42, 0), "No Next Header for IPv6"),
    ((43, 0), "Destination Unreachable for IPv6"),
    ((44, 0), "Packet Too Big for IPv6"),
    ((45, 0), "Time Exceeded for IPv6"),
    ((46, 0), "Parameter Problem for IPv6"),
    ((47, 0), "Echo Request for IPv6"),
    ((48, 0), "Echo Reply for IPv6"),
    ((49, 0), "Multicast Listener Query for IPv6"),
    ((50, 0), "Multicast Listener Report for IPv6"),
    ((51, 0), "Multicast Listener Done for IPv6"),
    ((58, 0), "Router Solicitation for IPv6"),
    ((59, 0), "Router Advertisement for IPv6"),
    ((60, 0), "Neighbor Solicitation for IPv6"),
    ((61, 0), "Neighbor Advertisement for IPv6"),
    ((62, 0), "Redirect Message for IPv6"),
];

#[allow(dead_code)]
struct IP {
    ver_ihl: u8,
    tos: u8,
    len: u16,
    id: u16,
    offset: u16,
    ttl: u8,
    protocol_num: u8,
    sum: u16,
    src: u32,
    dst: u32,
}

impl IP {
    fn new(buff: &[u8]) -> Option<Self> {
        if buff.len() >= 20 {
            let header = IP {
                ver_ihl: buff[0],
                tos: buff[1],
                len: u16::from_be_bytes([buff[2], buff[3]]),
                id: u16::from_be_bytes([buff[4], buff[5]]),
                offset: u16::from_be_bytes([buff[6], buff[7]]),
                ttl: buff[8],
                protocol_num: buff[9],
                sum: u16::from_be_bytes([buff[10], buff[11]]),
                src: u32::from_be_bytes([buff[12], buff[13], buff[14], buff[15]]),
                dst: u32::from_be_bytes([buff[16], buff[17], buff[18], buff[19]]),
            };

            Some(header)
        } else {
            None
        }
    }

    fn protocol(&self) -> String {
        // Refer to ---> https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        match self.protocol_num {
            0 => String::from("HOPOPT"),
            1 => String::from("ICMP"),
            2 => String::from("IGMP"),
            3 => String::from("GGP"),
            4 => String::from("IPv4"),
            5 => String::from("ST"),
            6 => String::from("TCP"),
            7 => String::from("CBT"),
            8 => String::from("EGP"),
            9 => String::from("IGP"),
            10 => String::from("BBN-RCC-MON"),
            11 => String::from("NVP-II"),
            12 => String::from("PUP"),
            13 => String::from("ARGUS"),
            14 => String::from("EMCON"),
            15 => String::from("XNET"),
            16 => String::from("CHAOS"),
            17 => String::from("UDP"),
            18 => String::from("MUX"),
            19 => String::from("DCN-MEAS"),
            20 => String::from("HMP"),
            21 => String::from("PRM"),
            22 => String::from("XNS-IDP"),
            23 => String::from("TRUNK-1"),
            24 => String::from("TRUNK-2"),
            25 => String::from("LEAF-1"),
            26 => String::from("LEAF-2"),
            27 => String::from("RDP"),
            28 => String::from("IRTP"),
            29 => String::from("ISO-TP4"),
            30 => String::from("NETBLT"),
            31 => String::from("MFE-NSP"),
            32 => String::from("MERIT-INP"),
            33 => String::from("DCCP"),
            34 => String::from("3PC"),
            35 => String::from("IDPR"),
            36 => String::from("XTP"),
            37 => String::from("DDP"),
            38 => String::from("IDPR-CMTP"),
            39 => String::from("TP++"),
            40 => String::from("IL"),
            41 => String::from("IPv6"),
            42 => String::from("SDRP"),
            43 => String::from("IPv6-Route"),
            44 => String::from("IPv6-Frag"),
            45 => String::from("IDRP"),
            46 => String::from("RSVP"),
            47 => String::from("GRE"),
            48 => String::from("DSR"),
            49 => String::from("BNA"),
            50 => String::from("ESP"),
            51 => String::from("AH"),
            52 => String::from("I-NLSP"),
            53 => String::from("SWIPE (deprecated)"),
            54 => String::from("NARP"),
            55 => String::from("MOBILE"),
            56 => String::from("TLSP"),
            57 => String::from("SKIP"),
            58 => String::from("IPv6-ICMP"),
            59 => String::from("IPv6-NoNxt"),
            60 => String::from("IPv6-Opts"),
            61 => String::from("any host internal protocol"),
            62 => String::from("CFTP"),
            63 => String::from("any local network"),
            64 => String::from("SAT-EXPAK"),
            65 => String::from("KRYPTOLAN"),
            66 => String::from("RVD"),
            67 => String::from("IPPC"),
            68 => String::from("any distributed file system"),
            69 => String::from("SAT-MON"),
            70 => String::from("VISA"),
            71 => String::from("IPCV"),
            72 => String::from("CPNX"),
            73 => String::from("CPHB"),
            74 => String::from("WSN"),
            75 => String::from("PVP"),
            76 => String::from("BR-SAT-MON"),
            77 => String::from("SUN-ND"),
            78 => String::from("WB-MON"),
            79 => String::from("WB-EXPAK"),
            80 => String::from("ISO-IP"),
            81 => String::from("VMTP"),
            82 => String::from("SECURE-VMTP"),
            83 => String::from("VINES"),
            84 => String::from("IPTM"),
            85 => String::from("NSFNET-IGP"),
            86 => String::from("DGP"),
            87 => String::from("TCF"),
            88 => String::from("EIGRP"),
            89 => String::from("OSPFIGP"),
            90 => String::from("Sprite-RPC"),
            91 => String::from("LARP"),
            92 => String::from("MTP"),
            93 => String::from("AX.25"),
            94 => String::from("IPIP"),
            95 => String::from("MICP (deprecated)"),
            96 => String::from("SCC-SP"),
            97 => String::from("ETHERIP"),
            98 => String::from("ENCAP"),
            100 => String::from("GMTP"),
            101 => String::from("IFMP"),
            102 => String::from("PNNI"),
            103 => String::from("PIM"),
            104 => String::from("ARIS"),
            105 => String::from("SCPS"),
            106 => String::from("QNX"),
            107 => String::from("A/N"),
            108 => String::from("IPComp"),
            109 => String::from("SNP"),
            110 => String::from("Compaq-Peer"),
            111 => String::from("IPX-in-IP"),
            112 => String::from("VRRP"),
            113 => String::from("PGM"),
            114 => String::from("any 0-hop protocol"),
            115 => String::from("L2TP"),
            116 => String::from("DDX"),
            117 => String::from("IATP"),
            118 => String::from("STP"),
            119 => String::from("SRP"),
            120 => String::from("UTI"),
            121 => String::from("SMP"),
            122 => String::from("SM (deprecated)"),
            123 => String::from("PTP"),
            124 => String::from("ISIS over IPv4"),
            125 => String::from("FIRE"),
            126 => String::from("CRTP"),
            127 => String::from("CRUDP"),
            128 => String::from("SSCOPMCE"),
            129 => String::from("IPLT"),
            130 => String::from("SPS"),
            131 => String::from("PIPE"),
            132 => String::from("SCTP"),
            133 => String::from("FC"),
            134 => String::from("RSVP-E2E-IGNORE"),
            135 => String::from("Mobility Header"),
            136 => String::from("UDPLite"),
            137 => String::from("MPLS-in-IP"),
            138 => String::from("manet"),
            139 => String::from("HIP"),
            140 => String::from("Shim6"),
            141 => String::from("WESP"),
            142 => String::from("ROHC"),
            143 => String::from("Ethernet"),
            144 => String::from("AGGFRAG"),
            145 => String::from("NSH"),
            146..=252 => String::from("Unassigned"),
            253 => String::from("Use for experimentation and testing"),
            254 => String::from("Use for experimentation and testing"),
            255 => String::from("Reserved"),
            _ => format!("{}", self.protocol_num),
        }
    }

    fn src_address(&self) -> String {
        Ipv4Addr::from(self.src).to_string()
    }

    fn dst_address(&self) -> String {
        Ipv4Addr::from(self.dst).to_string()
    }

    fn offset(&self) -> String {
        self.offset.to_string()
    }

    fn ttl(&self) -> String {
        self.ttl.to_string()
    }

    fn ver(&self) -> String {
        self.ver_ihl.to_string()
    }

    fn len(&self) -> String {
        self.len.to_string()
    }
}

#[allow(dead_code)]
struct ICMP {
    type_: u8,
    code: u8,
    sum: u16,
    id: u16,
    seq: u16,
}

impl ICMP {
    fn new(buff: &[u8]) -> Self {
        let header = (
            buff[0],
            buff[1],
            u16::from_be_bytes([buff[2], buff[3]]),
            u16::from_be_bytes([buff[4], buff[5]]),
            u16::from_be_bytes([buff[6], buff[7]]),
        );
        ICMP {
            type_: header.0,
            code: header.1,
            sum: header.2,
            id: header.3,
            seq: header.4,
        }
    }
}

fn icmp_type_name(type_: u8, code: u8) -> String {
    for &((t, c), name) in ICMP_TYPE_CODE_MAP {
        if t == type_ && (c == code || c == 255) {
            return name.to_string();
        }
    }
    format!("Type: {}, Code: {}", type_, code)
}

fn sniff(address: SocketAddr) {
    let socket_protocol = if cfg!(target_os = "windows") {
        0
    } else {
        1 // IPPROTO_ICMP
    };

    let sniffer = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(socket_protocol)),
    ).unwrap();
    sniffer.bind(&address.into()).unwrap();

    let mut buffer: [MaybeUninit<u8>; 65535] = unsafe { MaybeUninit::uninit().assume_init() };
    loop {
        let _length = sniffer.recv_from(&mut buffer).unwrap();
        let raw_buffer: &[u8] =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u8, buffer.len()) };

        if raw_buffer.len() < 20 {
            eprintln!("Invalid packet: too short");
            continue;
        }

        // Create an IP header from the first 20 bytes
        let ip_header = match IP::new(&raw_buffer[..20]) {
            Some(header) => header,
            None => {
                eprintln!("Failed to parse IP header");
                continue;
            }
        };

        // If it's ICMP, we want it
        if ip_header.protocol() == "ICMP" {
            println!(
                "Protocol: {} {} -> {}",
                "ICMP",
                ip_header.src_address(),
                ip_header.dst_address()
            );
            println!("Version: {}", ip_header.ver());
            println!(
                "Header Length: {} TTL: {}",
                ip_header.len(),
                ip_header.ttl()
            );

            // Calculate where our ICMP packet starts
            let offset = ip_header.offset().parse().unwrap_or_else(|_| {
                eprintln!("Failed to parse offset");
                0
            });
            if offset + 8 <= raw_buffer.len() {
                let buf = &raw_buffer[offset..offset + 8];
                // Create our ICMP structure
                let icmp_header = ICMP::new(buf);
                println!(
                    "ICMP -> {}",
                    icmp_type_name(icmp_header.type_, icmp_header.code)
                );
            } else {
                eprintln!("Invalid ICMP packet: too short");
            }
        }
    }
}

fn main() {
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12345);

    sniff(socket);
}
