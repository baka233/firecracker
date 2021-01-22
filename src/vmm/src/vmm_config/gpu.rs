use devices::virtio::gpu::device::Gpu;
use std::sync::{Mutex, Arc};
use devices::virtio::gpu::{Error as GpuError, GpuMode};
use crate::vmm_config::gpu::GpuConfigError::CreateGpuFailed;
use serde::{Deserialize, Serialize};
use logger::info;
use std::fmt::{Display, Formatter};
use std::fmt;

type MutexGpu = Arc<Mutex<Gpu>>;
type Result<T> = std::result::Result<T, GpuConfigError>;

#[derive(Debug)]
/// Gpu config error enum
pub enum GpuConfigError {
    /// Create gpu failed
    CreateGpuFailed(GpuError)
}

impl From<GpuError> for GpuConfigError {
    fn from(e: GpuError) -> Self {
        CreateGpuFailed(e)
    }
}

impl Display for GpuConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CreateGpuFailed(e) => write!(f, "Create gpu failed, err: {:?}", e)
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// gpu device configuration
pub struct GpuDeviceConfig {
}

#[derive(Default)]
/// Gpu builder
pub struct GpuBuilder {
    /// inner filed implement the only instance of gpu
    inner: Option<MutexGpu>
}

impl GpuBuilder {
    /// create new Gpu builder instance
    pub fn new() -> Self {
        Self {
            inner: None
        }
    }

    /// insert the new config and build the gpu
    pub fn insert(&mut self, _config: GpuDeviceConfig) -> Result<()> {
        self.inner = Some(Arc::new(Mutex::new(Gpu::new(
            GpuMode::Mode3D
        )?)));
        info!("Gpu: init gpu device successfully");
        Ok(())
    }

    /// get the gpu instance
    pub fn get(&self) -> Option<&MutexGpu> {
        self.inner.as_ref()
    }
}