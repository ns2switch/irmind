use super::EventSchemaError;
macro_rules! codes {
    ($name:ident, $(($variant:ident, $label:literal, $code:literal)),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn code(self) -> u16 { match self { $(Self::$variant => $code),+ } }
            pub const fn as_str(self) -> &'static str { match self { $(Self::$variant => $label),+ } }
            pub fn from_code(code:u16) -> Result<Self,EventSchemaError> {
                Self::ALL.iter().copied().find(|v|v.code()==code).ok_or(EventSchemaError::UnknownCode)
            }
            pub fn parse(label:&str) -> Result<Self,EventSchemaError> {
                Self::ALL.iter().copied().find(|v|v.as_str()==label).ok_or(EventSchemaError::UnknownCode)
            }
        }
    };
}

codes!(
    EventCategory,
    (Api, "api", 0),
    (Authentication, "authentication", 1),
    (Configuration, "configuration", 2),
    (Database, "database", 3),
    (Driver, "driver", 4),
    (Email, "email", 5),
    (File, "file", 6),
    (Host, "host", 7),
    (Iam, "iam", 8),
    (IntrusionDetection, "intrusion_detection", 9),
    (Library, "library", 10),
    (Malware, "malware", 11),
    (Network, "network", 12),
    (Package, "package", 13),
    (Process, "process", 14),
    (Registry, "registry", 15),
    (Session, "session", 16),
    (Threat, "threat", 17),
    (Vulnerability, "vulnerability", 18),
    (Web, "web", 19),
);

codes!(
    EventType,
    (Access, "access", 0),
    (Admin, "admin", 1),
    (Allowed, "allowed", 2),
    (Change, "change", 3),
    (Connection, "connection", 4),
    (Creation, "creation", 5),
    (Deletion, "deletion", 6),
    (Denied, "denied", 7),
    (Device, "device", 8),
    (End, "end", 9),
    (Error, "error", 10),
    (Group, "group", 11),
    (Indicator, "indicator", 12),
    (Info, "info", 13),
    (Installation, "installation", 14),
    (Protocol, "protocol", 15),
    (Start, "start", 16),
    (User, "user", 17),
);

codes!(
    EventOutcome,
    (Unknown, "unknown", 0),
    (Success, "success", 1),
    (Failure, "failure", 2),
);

codes!(
    EventKind,
    (Event, "event", 0),
    (Alert, "alert", 1),
    (State, "state", 2),
);

codes!(
    EntityRole,
    (Actor, "actor", 1),
    (Target, "target", 2),
    (Source, "source", 3),
    (Destination, "destination", 4),
    (Parent, "parent", 5),
    (Subject, "subject", 6),
    (Observer, "observer", 7),
    (Related, "related", 8),
);
