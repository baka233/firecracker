use devices::virtio::fpga::device::Fpga;
use devices::virtio::fpga::{Error as FpgaError, Error};
use std::sync::{Mutex, Arc};
use crate::vmm_config::fpga::FpgaConfigError::CreateFpgaFailed;
use std::fmt::Display;
use serde::__private::Formatter;
use std::fmt;
use serde::{Deserialize, Serialize};
use logger::info;

type MutexFpga = Arc<Mutex<Fpga>>;
type Result<T> = std::result::Result<T, FpgaConfigError>;

#[derive(Debug)]
/// Fpga config error enum
pub enum FpgaConfigError {
    /// Create fpga failed
    CreateFpgaFailed(FpgaError)
}

impl From<FpgaError> for FpgaConfigError {
    fn from(e: Error) -> Self {
        CreateFpgaFailed(e)
    }
}

impl Display for FpgaConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CreateFpgaFailed(e) => write!(f, "Create fpga failed, err: {:?}", e)
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
/// fpga device configuration
pub struct FpgaDeviceConfig {
    /// fme path, eg: /sys/class/fpga_region/region[0-9]+/dfl-fme.0
    fme_path:   Option<String>,
    /// port path eg: /sys/class/fpga_region/region[0-9]+/dfl-port.0
    port_paths: Vec<String>,
}

#[derive(Default)]
/// Fpga builder
pub struct FpgaBuilder {
    /// inner struct to store the fpga virtio instance
    inner: Option<MutexFpga>
}

impl FpgaBuilder {
    /// create new Fpga builder instance
    pub fn new() -> Self {
        Self {
            inner: None
        }
    }

    /// insert the new config and build the fpga
    pub fn insert(&mut self, config: FpgaDeviceConfig) -> Result<()> {
        self.inner = Some(Arc::new(Mutex::new(Fpga::new(
            config.fme_path.as_ref(),
            config.port_paths
        )?)));
        info!("Fpga: init fpga device successfully");
        Ok(())
    }

    /// get the fpga instance
    pub fn get(&self) -> Option<&MutexFpga> { self.inner.as_ref() }
}