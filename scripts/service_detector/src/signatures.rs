use lazy_static::lazy_static;
use regex::Regex;

pub struct Signature {
    pub service: &'static str,
    pub regex: Regex,
}

lazy_static! {
    pub static ref SIGNATURES: Vec<Signature> = vec![
        Signature {
            service: "SSH",
            regex: Regex::new(r"(?im)^SSH-(?P<version>[0-9.]+)-(?P<product>[^\r\n]+)")
                .expect("invalid SSH signature regex"),
        },
        Signature {
            service: "FTP",
            regex: Regex::new(r"(?im)^220(?:-|\s)(?P<version>[^\r\n]*(?:FTP|vsFTPd|ProFTPD|Pure-FTPd|FileZilla|Serv-U)[^\r\n]*)")
                .expect("invalid FTP signature regex"),
        },
        Signature {
            service: "SMTP",
            regex: Regex::new(r"(?im)^220(?:-|\s)(?P<version>[^\r\n]*(?:SMTP|ESMTP)[^\r\n]*)")
                .expect("invalid SMTP signature regex"),
        },
        Signature {
            service: "MySQL",
            regex: Regex::new(r"(?is)(?:mysql_native_password|mariadb|(?:^|\n)(?P<version>\d+\.\d+\.\d+[a-zA-Z0-9.\-]+)(?:\u{fffd}|[\x01-\x08\x0b-\x1f]))")
                .expect("invalid MySQL signature regex"),
        },
        Signature {
            service: "Samba/SMB",
            regex: Regex::new(r"(?is)SMB.*?(\x00|%|WORKGROUP|LANMAN)")
                .expect("invalid Samba/SMB signature regex"),
        },
        Signature {
            service: "VNC",
            regex: Regex::new(r"(?im)^RFB\s+(?P<version>\d{3}\.\d{3})")
                .expect("invalid VNC signature regex"),
        },
        Signature {
            service: "IRC",
            regex: Regex::new(r"(?im)(?:NOTICE\s+AUTH|^:[^\s]+\s+001\s+\S+\s+:|irc\.Metasploitable\.LAN)")
                .expect("invalid IRC signature regex"),
        },
        Signature {
            service: "Apache",
            regex: Regex::new(r"(?im)^Server:\s*Apache(?:/(?P<version>[\w.\-]+))?")
                .expect("invalid Apache signature regex"),
        },
        Signature {
            service: "Nginx",
            regex: Regex::new(r"(?im)^Server:\s*nginx(?:/(?P<version>[\w.\-]+))?")
                .expect("invalid Nginx signature regex"),
        },
        Signature {
            service: "Tomcat",
            regex: Regex::new(r"(?im)(?:^Server:\s*Apache-Coyote(?:/(?P<version>[\w.\-]+))?|tomcat)")
                .expect("invalid Tomcat signature regex"),
        },
        Signature {
            service: "Telnet (Unauthenticated)",
            regex: Regex::new(r"(?im)(?:^\u{fffd}{2,}\s*$|^[\x01-\x1f]{2,}\s*$|^\s*login:\s*$|^\s*password:\s*$|^\s*Escape character is)")
                .expect("invalid Telnet (Unauthenticated) signature regex"),
        },
        Signature {
            service: "Bindshell",
            regex: Regex::new(r"(?im)(?:^uid=\d+\(.+?\)\s+gid=\d+\(|root@|#\s*$|Microsoft Windows \[Version)")
                .expect("invalid Bindshell signature regex"),
        },
    ];
}