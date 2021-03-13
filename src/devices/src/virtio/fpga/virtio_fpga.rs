use crate::virtio::fpga::afu::VirtioFpgaAfu;
use std::collections::BTreeMap;
use mem_control::MemRequest;
use std::sync::{Mutex, Arc};
use crate::virtio::fpga::Error;
use crate::virtio::fpga::fme::VirtioFpgaFme;
use crate::virtio::fpga::protocol::{VirtioFpgaCommand, VirtioFpgaResponse};

pub(crate) struct VirtioFpga {
    pub port_num:  usize,
    pub afu_paths: Vec<String>,
    pub fme_path:  Option<String>,

    pub afus:   BTreeMap<u32, VirtioFpgaAfu>,
    pub fme:    Option<VirtioFpgaFme>,
}

impl VirtioFpga {
    pub fn new(
        fme_path: Option<String>,
        afu_paths: &Vec<String>,
        mem_controller: Arc<Mutex<dyn MemRequest + Send>>
    ) -> Result<Self, Error> {
        let mut afus = BTreeMap::new();
        let mut fme = None;

        if let Some(ref path) = fme_path {
            fme = Some(VirtioFpgaFme::from_path(path)?);
        }

        for (i, afu_path) in afu_paths.iter().enumerate()  {
            let afu = VirtioFpgaAfu::from_path(i as u32, &afu_path, mem_controller.clone())?;
            afus.insert(i as u32, afu);
        }

        return Ok(VirtioFpga {
            port_num: afu_paths.len(),
            afu_paths: afu_paths.clone(),
            fme_path: fme_path.clone(),
            afus,
            fme,
        })
    }

    pub(crate) fn process_afu_request(
        &mut self,
        port_id: u32,
        command: &VirtioFpgaCommand
    ) -> Result<VirtioFpgaResponse, VirtioFpgaResponse> {
        let afu = self.afus.get_mut(&port_id)
            .ok_or(VirtioFpgaResponse::ErrPortNotExist(port_id))?;

        #[allow(unreachable_patterns)]
        match command {
            VirtioFpgaCommand::VirtioFpgaAfuPortInfo(cmd) => {
                afu.get_port_info(cmd)
            }
            VirtioFpgaCommand::VirtioFpgaAfuRegionInfo(cmd) => {
                afu.get_region_info(cmd)
            }
            VirtioFpgaCommand::VirtioFpgaAfuDmaMap(cmd) => {
                afu.map_dma_region(cmd)
            }
            VirtioFpgaCommand::VirtioFpgaAfuDmaUnmap(cmd) => {
                afu.unmap_dma_region(cmd)
            }
            _ => Err(VirtioFpgaResponse::ErrUnspec),
        }
    }

    pub(crate) fn process_fme_request(
        &mut self,
        command: &VirtioFpgaCommand
    ) -> Result<VirtioFpgaResponse, VirtioFpgaResponse> {
        match command {
            _ => Err(VirtioFpgaResponse::ErrUnspec)
        }
    }
}

