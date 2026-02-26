use regex::Regex;
use lazy_static::lazy_static;

pub struct Signature {
    pub service: &'static str,
    pub regex: Regex,
}

lazy_static! {
    pub static ref SIGNATURES: Vec<Signature> = vec![
        Signature {
            service: "SSH",
            regex: Regex::new(r"(?im)^SSH-(?P<version>[0-9.]+-[^\r\n]+)").unwrap(),
        },
        Signature {
            service: "FTP",
            regex: Regex::new(r"(?im)^220(?:-|\s)(?P<version>[^\r\n]*(?:FTP|vsFTPd|ProFTPD|Pure-FTPd|FileZilla|Serv-U)[^\r\n]*)").unwrap(),
        },
        Signature {
            service: "SMTP",
            regex: Regex::new(r"(?im)^220(?:-|\s)(?P<version>[^\r\n]*(?:SMTP|ESMTP|Postfix|Sendmail)[^\r\n]*)").unwrap(),
        },
        Signature {
            service: "MySQL",
            // Firma estricta: solo si vemos los identificadores binarios del protocolo
            regex: Regex::new(r"(?is)(?:mysql_native_password|mariadb)").unwrap(),
        },
        Signature {
            service: "VNC",
            regex: Regex::new(r"(?im)^RFB\s+(?P<version>\d{3}\.\d{3})").unwrap(),
        },
        Signature {
            service: "IRC",
            regex: Regex::new(r"(?im)(?:NOTICE\s+AUTH|^:[^\s]+\s+001\s+\S+\s+:|irc\.[a-zA-Z0-9.\-]+)").unwrap(),
        },
        Signature {
            service: "Apache",
            regex: Regex::new(r"(?im)^Server:\s*(?P<version>Apache(?:/[\w.\-]+)?)").unwrap(),
        },
        Signature {
            service: "Nginx",
            regex: Regex::new(r"(?im)^Server:\s*(?P<version>nginx(?:/[\w.\-]+)?)").unwrap(),
        },
        Signature {
            service: "Tomcat",
            regex: Regex::new(r"(?im)(?:^Server:\s*(?P<version>Apache-Coyote(?:/[\w.\-]+)?)|tomcat)").unwrap(),
        },
        Signature {
            service: "Bindshell",
            regex: Regex::new(r"(?im)(?:^uid=\d+\(.+?\)\s+gid=\d+\(|root@|#\s*$|Microsoft Windows \[Version)").unwrap(),
        },
        Signature {
            service: "Samba/SMB",
            regex: Regex::new(r"(?is)(?:|\xef\xbf\xbd|\xff)?SMB.*?(?:WORKGROUP|LANMAN|NT LM 0\.12)").unwrap(),
        },
        Signature {
            service: "Telnet",
            regex: Regex::new(r"(?im)(?:^\xff\xfd|Login:|password:|Escape character is)").unwrap(),
        },
    ];
}