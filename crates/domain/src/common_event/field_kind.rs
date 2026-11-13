use super::CommonValue;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommonFieldType {
    Boolean,
    Text,
    LongText,
    Ip,
    Port,
    Pid,
    Unsigned,
    HttpStatus,
    Time,
    Md5,
    Sha1,
    Sha256,
    Direction,
    TextList,
    DnsAnswers,
}
impl CommonFieldType {
    pub(super) fn accepts(self, value: &CommonValue) -> bool {
        use super::HashAlgorithm;
        match (self, value) {
            (Self::Text, CommonValue::Text(v)) => {
                v.as_str().len() <= 512 && !v.as_str().chars().any(char::is_control)
            }
            (Self::Boolean, CommonValue::Boolean(_))
            | (Self::LongText, CommonValue::Text(_))
            | (Self::Ip, CommonValue::Ip(_))
            | (Self::Unsigned, CommonValue::Unsigned(_))
            | (Self::Time, CommonValue::Time(_))
            | (Self::Direction, CommonValue::Direction(_))
            | (Self::TextList, CommonValue::TextList(_))
            | (Self::DnsAnswers, CommonValue::DnsAnswers(_)) => true,
            (Self::Port, CommonValue::Unsigned(v)) => u16::try_from(*v).is_ok(),
            (Self::Pid, CommonValue::Unsigned(v)) => u32::try_from(*v).is_ok(),
            (Self::HttpStatus, CommonValue::Unsigned(v)) => (100..=599).contains(v),
            (Self::Md5, CommonValue::Hash(v)) => v.algorithm() == HashAlgorithm::Md5,
            (Self::Sha1, CommonValue::Hash(v)) => v.algorithm() == HashAlgorithm::Sha1,
            (Self::Sha256, CommonValue::Hash(v)) => v.algorithm() == HashAlgorithm::Sha256,
            _ => false,
        }
    }
}
