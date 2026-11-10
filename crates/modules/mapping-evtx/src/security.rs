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
        "20affc8fd4c2b9d508806b45bf36d090552e71aea9470151d38c0415695c5e56",
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
        "d2780c8595d8ccbfe0eacc252cd4e54c02353fc9b803ed1a69423406d3a36a19",
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
        "74268bc5639842d527ca910ad3c00988382d0f0e92744ccd855fffe966ba25e3",
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
        "4f31007c76887153338df3771d878836dc2a01cb731b2b4419012cba8f46e8f4",
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
        "84ae726315285456e0e4dfd0274b7f114d6fc74df38a8fb8374affe0176ad477",
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
        "f039708bb47ecf0aa0626eea5a3bf560b5c1c4462dec40e4d232f844f5248572",
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
        "9ec0d58119538c639f70bc37c1e6135a50765fadb61f71714260cf6ac0b14cf9",
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
        "3a310d62fea4837215875b9b5601adeead11b4735fc14798f420ef074a455d20",
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
        "832364944b5c7a1618dab64029dc5ef8c8487b052031c213086c5371fbc8f7ea",
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
        "5f24792310e0873b7c2fa8ad8c052a961bc457b23edcfd889046eefd81a5417d",
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
        "379539af4d5003733774c4c39a0db8f59a4489d7d50283a8b423f811fda13965",
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
        "8d8895210ae7c361fc60b2b66de29371f9e47607a31a565c7dc0b1e134e25908",
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
        "46f1d36c623989980ce6fded38846f9ddc623d5298906cf7348ce4e88f0228a0",
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
        "211518b5744815f9b166e4c4071db324012d31f5be5f4571fdd59f9c14f7cbdf",
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
        "9314c36d5618662561002fa3f473190a1ace2c972f3f9861b1c89c207b93a6ff",
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
        "e511dd0e683ed24f95a6078984770de3a78c36bc702c0b0c2d5b05bec7e56ea5",
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
        "218eb380c267b4b15bf6cee0cbff9de59423fcf1118dcf11c51210696a5e9cae",
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
