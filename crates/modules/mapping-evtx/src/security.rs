use irmind_app::{
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
    source_mapping::{MappingError, MappingManifest, MappingOutput, SourceMapper, SourceRecordV1},
};
use irmind_domain::EvidenceHash;
use irmind_mapping_tables::TableMapping;
use std::sync::Arc;
type Entry = (u16, &'static str, &'static str, ModuleManifest);
const DEFINITIONS: &[Entry] = &[
    (
        4624,
        include_str!("tables/security-4624.toml"),
        "42ec6a07ac967e1d05fbf6e6dc63d0a263fba0f61ec171797a213f2ad7a982a4",
        ModuleManifest {
            id: "mapping-evtx-security-4624",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4625,
        include_str!("tables/security-4625.toml"),
        "33cb565955140ff5240f95d3854fc98fa25cd89dbf525e71d8f1d3efe950340b",
        ModuleManifest {
            id: "mapping-evtx-security-4625",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4634,
        include_str!("tables/security-4634.toml"),
        "2ce8c5ee7aa53a1f3272347574119b73bba14798b210879f5cf32f1d5f43b269",
        ModuleManifest {
            id: "mapping-evtx-security-4634",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4648,
        include_str!("tables/security-4648.toml"),
        "42e5175757ce823d19fa1d137ded3ecd8cb51a107cb3def39f18d60304c3addb",
        ModuleManifest {
            id: "mapping-evtx-security-4648",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4672,
        include_str!("tables/security-4672.toml"),
        "1790dd579949b1c15623c51a635358e28d452edaee3d2c02bade0bc7432a8c0c",
        ModuleManifest {
            id: "mapping-evtx-security-4672",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4688,
        include_str!("tables/security-4688.toml"),
        "ef14b587e95372fea461e59142ecd411954a5fef3e8784052284fc8e5876e795",
        ModuleManifest {
            id: "mapping-evtx-security-4688",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4697,
        include_str!("tables/security-4697.toml"),
        "c3c25344e079d80a7f74279686d94c4c2148fd55e5fb52f96fc4287e65720bdc",
        ModuleManifest {
            id: "mapping-evtx-security-4697",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4720,
        include_str!("tables/security-4720.toml"),
        "df48a23b04b730691f6a66074b123ee59749132a33efb9a6aed4ff2a493ab5f3",
        ModuleManifest {
            id: "mapping-evtx-security-4720",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4722,
        include_str!("tables/security-4722.toml"),
        "39610fc2d2ca74e3ddaae9e2667250603f1a02c03e4ec8a2d9ba4211f9ea45df",
        ModuleManifest {
            id: "mapping-evtx-security-4722",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4724,
        include_str!("tables/security-4724.toml"),
        "0e435ffb14bccdabaccf2a95ecfa3e4c2cb8f012f19ce7e99a27fbd046cbf264",
        ModuleManifest {
            id: "mapping-evtx-security-4724",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4728,
        include_str!("tables/security-4728.toml"),
        "31821c6217bbf7227db8bf5ee71dd87963d62a56b00b6e50d3f703b7d88de095",
        ModuleManifest {
            id: "mapping-evtx-security-4728",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4732,
        include_str!("tables/security-4732.toml"),
        "91946da4b8a9bdde343fb1443c9b5811cd6685e8f4636e7dc555be16759101dc",
        ModuleManifest {
            id: "mapping-evtx-security-4732",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4756,
        include_str!("tables/security-4756.toml"),
        "980e9394d3e361d0155b5c77a2d45b6a7fbda3a2f0677caf5200ea601aba9feb",
        ModuleManifest {
            id: "mapping-evtx-security-4756",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4768,
        include_str!("tables/security-4768.toml"),
        "93446f51d5d1d793707ffab2c9159d5aa1c310bf8ac61f91c3e44af7586f44ec",
        ModuleManifest {
            id: "mapping-evtx-security-4768",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4769,
        include_str!("tables/security-4769.toml"),
        "b4b12975ec46769ab43d1567b770fcd59fc8bb3c2d979450afb4a9e3a318d580",
        ModuleManifest {
            id: "mapping-evtx-security-4769",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4771,
        include_str!("tables/security-4771.toml"),
        "9360c361008b792b5f7993e847374e48a341b25dcb8381fc7260bf073689b480",
        ModuleManifest {
            id: "mapping-evtx-security-4771",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
    (
        4776,
        include_str!("tables/security-4776.toml"),
        "f6d89c123fd3407d0d78cc45db5589ca7daafa1c93b1f81c5e55291b1a59dacc",
        ModuleManifest {
            id: "mapping-evtx-security-4776",
            version: "0.1.0",
            ports: &[ModulePort::SourceMapper],
            tools: &[],
            config: &[],
        },
    ),
];
pub struct SecurityMapping {
    table: TableMapping,
    module: &'static ModuleManifest,
}
impl SecurityMapping {
    pub const EVENT_IDS: &'static [u16] = &[
        4624, 4625, 4634, 4648, 4672, 4688, 4697, 4720, 4722, 4724, 4728, 4732, 4756, 4768, 4769,
        4771, 4776,
    ];
    pub fn new(event_id: u16) -> Result<Self, MappingError> {
        let (_, contents, digest, module) = DEFINITIONS
            .iter()
            .find(|entry| entry.0 == event_id)
            .ok_or(MappingError::InvalidDefinition)?;
        let expected = EvidenceHash::parse(digest).map_err(|_| MappingError::InvalidDefinition)?;
        Ok(Self {
            table: TableMapping::bundled(contents, &expected)?,
            module,
        })
    }
}
impl SourceMapper for SecurityMapping {
    fn manifest(&self) -> &MappingManifest {
        self.table.manifest()
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        self.table.map(source)
    }
}
impl Module for SecurityMapping {
    fn manifest(&self) -> &'static ModuleManifest {
        self.module
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), irmind_app::AppError> {
        registry.add_source_mapper(Arc::new(*self))
    }
}
