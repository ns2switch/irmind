#![forbid(unsafe_code)]

//! Explicit, read-only S3, GCS, and Azure Blob connectors.

#[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
mod backend;
#[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
mod connector;
mod port;

#[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
use irmind_app::modules::{ConfigField, ModulePort};
use irmind_app::{
    AppError,
    modules::{Module, ModuleConfig, ModuleManifest, ModuleRegistry},
};
#[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
use irmind_domain::Tool;
use object_store::ObjectStore;
use std::sync::Arc;

pub struct StorageObject {
    source_id: String,
    container: String,
    scheme: &'static str,
    store: Arc<dyn ObjectStore>,
    manifest: &'static ModuleManifest,
}

#[cfg(feature = "s3")]
pub static S3_MANIFEST: ModuleManifest = ModuleManifest {
    id: "storage-s3",
    version: "0.1.0",
    ports: &[ModulePort::ObjectSource],
    tools: &[Tool::ObjectList, Tool::ObjectRead],
    config: &[
        ConfigField {
            name: "IRMIND_STORAGE_S3_SOURCE_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_STORAGE_S3_BUCKET",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_STORAGE_S3_REGION",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_STORAGE_S3_ENDPOINT",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "AWS_ACCESS_KEY_ID",
            required: true,
            secret: true,
        },
        ConfigField {
            name: "AWS_SECRET_ACCESS_KEY",
            required: true,
            secret: true,
        },
        ConfigField {
            name: "AWS_SESSION_TOKEN",
            required: false,
            secret: true,
        },
    ],
};

#[cfg(feature = "gcs")]
pub static GCS_MANIFEST: ModuleManifest = ModuleManifest {
    id: "storage-gcs",
    version: "0.1.0",
    ports: &[ModulePort::ObjectSource],
    tools: &[Tool::ObjectList, Tool::ObjectRead],
    config: &[
        ConfigField {
            name: "IRMIND_STORAGE_GCS_SOURCE_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_STORAGE_GCS_BUCKET",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_STORAGE_GCS_ENDPOINT",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "GCP_SERVICE_ACCOUNT_JSON",
            required: true,
            secret: true,
        },
    ],
};

#[cfg(feature = "azure")]
pub static AZURE_MANIFEST: ModuleManifest = ModuleManifest {
    id: "storage-azure",
    version: "0.1.0",
    ports: &[ModulePort::ObjectSource],
    tools: &[Tool::ObjectList, Tool::ObjectRead],
    config: &[
        ConfigField {
            name: "IRMIND_STORAGE_AZURE_SOURCE_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_STORAGE_AZURE_ACCOUNT",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_STORAGE_AZURE_CONTAINER",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_STORAGE_AZURE_CLIENT_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_STORAGE_AZURE_TENANT_ID",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_STORAGE_AZURE_ENDPOINT",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "AZURE_CLIENT_SECRET",
            required: true,
            secret: true,
        },
    ],
};

impl Module for StorageObject {
    fn manifest(&self) -> &'static ModuleManifest {
        self.manifest
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_object_source(self)
    }
}
