use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    pub static ref MAIL_FROM_RE: Regex =
        Regex::new(r"(?i)^FROM:\s*<([^<>]*)>(?:\s+(.*))?$").unwrap();
    pub static ref MAIL_SIZE_RE: Regex = Regex::new(r"(?i)^SIZE=(\d+)$").unwrap();
    pub static ref RCPT_TO_RE: Regex = Regex::new(r"(?i)^TO:\s*<([^<>\s]+)>$").unwrap();
}
