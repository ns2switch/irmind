// Frozen role-free aliases; changes require a new mapping identity.
pub(super) fn classify_field(key: &str, value: &str) -> Option<&'static str> {
    let key = key.to_ascii_lowercase();
    if value.is_empty() || value.len() > 512 {
        return None;
    }
    if key.contains("ipaddress") || key == "ip" || key.ends_with("_ip") {
        return Some("ip");
    }
    if key.contains("hostname") || key == "host" || key.ends_with("_host") {
        return Some("host");
    }
    if key.contains("username") || key == "user" || key == "principalid" {
        return Some("user");
    }
    if key == "arn" {
        return Some(if value.contains(":role/") {
            "role"
        } else {
            "identity"
        });
    }
    if key.contains("domain") {
        return Some("domain");
    }
    if key.contains("sha256") || key.contains("sha1") || key == "md5" {
        return Some("hash");
    }
    if key == "accesskeyid" {
        return Some("key");
    }
    if key.contains("accountid") {
        return Some("account");
    }
    None
}
