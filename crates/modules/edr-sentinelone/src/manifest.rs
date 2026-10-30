use crate::{ConfigField, ModuleManifest, ModulePort, Tool};

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "edr-sentinelone",
    version: "0.1.0",
    ports: &[ModulePort::Edr],
    tools: &[Tool::EdrHostInfo, Tool::EdrProcessTree, Tool::EdrDetections],
    config: &[
        ConfigField {
            name: "IRMIND_SENTINELONE_URL",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SENTINELONE_CA_PEM",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SENTINELONE_CA_SHA256",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SENTINELONE_SOURCE_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SENTINELONE_SITE_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SENTINELONE_API_TOKEN",
            required: true,
            secret: true,
        },
    ],
};
