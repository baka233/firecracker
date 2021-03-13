use vm_memory::{GuestRegionMmap, MmapRegion, GuestAddress, Bytes, MemoryRegionAddress, Address};
use crate::virtio::fpga::protocol::*;
use mem_control::{MemRequest, VmMemRequest, VmMemResponse};
use std::sync::{Mutex, Arc};
use mem_control::address_allocator::Alloc;
use std::collections::BTreeMap;
use crate::virtio::fpga::utils::generate_pfn;
use crate::virtio::fpga::Error;
use regex::Regex;
use logger::{error, debug};
use std::time::UNIX_EPOCH;


pub(crate) struct AfuDmaMapRegion {
    pub region:     Arc<GuestRegionMmap>,
    pub slot:       u32,
    pub alloc:      Alloc,
}

pub(crate) struct VirtioFpgaAfu {
    pub(crate) path:     String,
    // TODO: need to be replace with rawfd, test only
    pub(crate) fd:       u32,
    pub(crate) port_id:  u32,
    pub(crate) vport_id: u32,
    pub(crate) mem_controller: Arc<Mutex<dyn MemRequest + Send>>,
    pub(crate) dma_map_table:     BTreeMap<GuestAddress, AfuDmaMapRegion>,
}

impl VirtioFpgaAfu {
    pub(crate) fn from_path(
        vport_id: u32,
        afu_path: &String,
        mem_controller: Arc<Mutex<dyn MemRequest + Send>>
    ) -> Result<Self, Error> {
        // let file = File::open(afu_path.as_str()).map_err(Error::OpenAfu)?;

        Ok(VirtioFpgaAfu {
            path: afu_path.clone(),
            fd: 0,
            port_id: Self::parse_port_id(afu_path)?,
            vport_id,
            mem_controller,
            dma_map_table: Default::default(),
        })
    }

    fn parse_port_id(path: &String) -> Result<u32, Error> {
        let re = Regex::new(r".*dfl-port\.([0-9]+)").map_err(|_| Error::PortIdParse)?;
        let caps = re.captures(path).ok_or(Error::PortIdParse)?;

        let port_id : u32 = caps
            .get(1)
            .ok_or(Error::PortIdParse)?
            .as_str()
            .parse()
            .map_err(|_| Error::PortIdParse)?;

        return Ok(port_id)
    }

    pub(crate) fn get_port_info(
        &self,
        _command: &virtio_fpga_afu_port_info
    ) -> std::result::Result<VirtioFpgaResponse, VirtioFpgaResponse> {
        Ok(VirtioFpgaResponse::OkPortInfo {
            flags: 0,
            num_regions: 1,
            num_umsgs: 0,
        })
    }

    pub(crate) fn get_region_info(
        &self,
        command: &virtio_fpga_afu_region_info
    ) -> std::result::Result<VirtioFpgaResponse, VirtioFpgaResponse> {
        Ok(VirtioFpgaResponse::OkRegionInfo {
            flags: 0,
            size: 100,
            offset: 200,
        })
    }

    pub(crate) fn map_dma_region(
        &mut self,
        command: &virtio_fpga_afu_dma_map
    ) -> std::result::Result<VirtioFpgaResponse, VirtioFpgaResponse> {
        let mut mem_controller_lock = self.mem_controller
            .lock()
            .map_err(|_| VirtioFpgaResponse::ErrMemLock)?;
        let alloc = Alloc::FpgaDmaBuffer((self.port_id, std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u32));
        let vm_request = VmMemRequest::MemoryAllocate(
            alloc.clone(),
            command.length.to_native(),
            "dma buffer".to_string()
        );

        let response = mem_controller_lock
            .execute_vm_mem_request(vm_request)
            .map_err(|_| VirtioFpgaResponse::ErrMemLock)?;

        let (addr, len) = match response {
            VmMemResponse::MemoryAllocate(addr, len) => (addr, len),
            _ => {
                error!("fpga-afu: unexpected response type: {:?}", &response);
                return Err(VirtioFpgaResponse::ErrUnspec);
            }
        };

        debug!("addr at {:X}, len is {:X}", addr, len);

        let (pfn, num_page) = generate_pfn(GuestAddress(addr), len);
        let dma_region = Arc::new(GuestRegionMmap::new(
            MmapRegion::new(len as usize).map_err(VirtioFpgaResponse::ErrMmap)?,
            GuestAddress(addr),
        ).map_err(VirtioFpgaResponse::ErrVmMem)?);

        // TODO: test code, need to be removed with real device buffer
        dma_region.write_obj::<u32>(9, MemoryRegionAddress::new(0)).unwrap();
        dma_region.write("test_data".as_bytes(), MemoryRegionAddress::new(4)).unwrap();

        let vm_mem_set = VmMemRequest::SetKvmUserMem(dma_region.clone());

        let response = mem_controller_lock
            .execute_vm_mem_request(vm_mem_set)
            .map_err(VirtioFpgaResponse::ErrMemControl)?;

        let slot = match response {
            VmMemResponse::KvmUserMemMapped(slot) => slot,
            _ => {
                error!("fpga-afu: unexpected response type: {:?}", &response);
                return Err(VirtioFpgaResponse::ErrUnspec);
            }
        };

        let iova = 0xdead_beaf_dead_beaf;

        self.dma_map_table.insert(GuestAddress(iova), AfuDmaMapRegion {
            region: dma_region.clone(),
            slot,
            alloc,
        });

        debug!("virtio-fpga: pfn is {:x}, num_page is {}", pfn, num_page);

        Ok(VirtioFpgaResponse::OkDmaMap {
            iova,
            pfn,
            num_page,
        })
    }

    pub(crate) fn unmap_dma_region(
        &mut self,
        command: &virtio_fpga_afu_dma_unmap
    ) -> Result<VirtioFpgaResponse, VirtioFpgaResponse> {
        let iova = command.iova.to_native();

        match self.dma_map_table.get_mut(&GuestAddress(iova)) {
            Some(ref map) => {
                let slot = map.slot;
                let mut mem_controller_lock = self.mem_controller
                    .lock()
                    .map_err(|_| VirtioFpgaResponse::ErrMemLock)?;

                mem_controller_lock
                    .execute_vm_mem_request(VmMemRequest::UnsetKvmUserMem(slot))
                    .map_err(VirtioFpgaResponse::ErrMemControl)?;

                mem_controller_lock
                    .execute_vm_mem_request(VmMemRequest::MemoryRelease(map.alloc))
                    .map_err(VirtioFpgaResponse::ErrMemControl)?;
            },
            None => {
                return Err(VirtioFpgaResponse::ErrIovaNotExist);
            }
        }

        // remove region to release the mmap resource
        self.dma_map_table.remove(&GuestAddress(iova));

        Ok(VirtioFpgaResponse::OkNoData)
    }
}