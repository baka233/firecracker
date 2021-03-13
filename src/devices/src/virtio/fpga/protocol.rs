use vm_memory::{Le32, ByteValued, GuestMemoryMmap, GuestAddress, Bytes, Le64};
use crate::virtio::fpga::{Result, Error};
use crate::virtio::fpga::protocol::VirtioFpgaCommand::{VirtioFpgaAfuPortInfo, VirtioFpgaAfuRegionInfo, VirtioFpgaAfuDmaMap, VirtioFpgaAfuDmaUnmap};
use mem_control::VmMemError;
use logger::{error, debug};
use vm_memory::mmap::MmapRegionError;

pub const VIRTIO_FPGA_DEVICE_TYPE: u32 = 100;

pub const VIRTIO_FPGA_F_VFME: u32 = 0;

pub const VIRTIO_FPGA_UNDEFINED: u32 = 0;

/* fme command */
pub const VIRTIO_FPGA_CMD_FME_PORT_PR: u32 = 0x0100;

/* afu command */
pub const VIRTIO_FPGA_CMD_GET_PORT_INFO: u32         = 0x0200;
pub const VIRTIO_FPGA_CMD_GET_PORT_REGION_INFO: u32  = 0x0201;
pub const VIRTIO_FPGA_CMD_DMA_MAP: u32               = 0x0202;
pub const VIRTIO_FPGA_CMD_DMA_UNMAP: u32             = 0x0203;
pub const VIRTIO_FPGA_CMD_MMIO_MAP: u32              = 0x0204;

/* ok command */
pub const VIRTIO_FPGA_RESP_OK_NODATA: u32            = 0x1000;
pub const VIRTIO_FPGA_RESP_OK_PORT_INFO: u32         = 0x1001;
pub const VIRTIO_FPGA_RESP_OK_REGION_INFO: u32       = 0x1002;
pub const VIRTIO_FPGA_RESP_OK_DMA_REGION:u32         = 0x1003;
pub const VIRTIO_FPGA_RESP_OK_MMIO_MAP: u32          = 0x1004;

/* error command */
pub const VIRTIO_FPGA_RESP_ERR_UNSPEC: u32           = 0x1100;
pub const VIRTIO_FPGA_RESP_ERR_PORT_NOT_EXIST: u32   = 0x1101;
pub const VIRTIO_FPGA_RESP_ERR_IOVA_NOT_EIXST: u32   = 0x1102;

#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_fpga_config {
    pub port_num:       Le32,
}

#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_fpga_ctrl_hdr {
    pub(crate) type_:      Le32,
    pub(crate) flags:      Le32,
    pub(crate) port_id:    Le32,
    pub(crate) is_fme:     Le32,
    pub(crate) padding:    Le32,
}

unsafe impl ByteValued for virtio_fpga_ctrl_hdr {}

#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_fpga_afu_port_info {
    pub(crate) hdr:        virtio_fpga_ctrl_hdr,
}

unsafe impl ByteValued for virtio_fpga_afu_port_info {}

#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_fpga_afu_resp_port_info {
    pub(crate) hdr:         virtio_fpga_ctrl_hdr,
    pub(crate) flags:       Le32,
    pub(crate) num_regions: Le32,
    pub(crate) num_umsgs:   Le32,
}

unsafe impl ByteValued for virtio_fpga_afu_resp_port_info {}

#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_fpga_afu_region_info {
    pub(crate) hdr:        virtio_fpga_ctrl_hdr,
    index:      Le32,
    padding:    Le32,
}

unsafe impl ByteValued for virtio_fpga_afu_region_info {}

#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_fpga_afu_resp_region_info {
    pub(crate) hdr:        virtio_fpga_ctrl_hdr,
    pub(crate) flags:      Le32,
    pub(crate) padding:    Le32,
    pub(crate) size:       Le64,
    pub(crate) offset:     Le64,
}

unsafe impl ByteValued for virtio_fpga_afu_resp_region_info {}

#[derive(Debug, Copy, Clone, Default)]
pub struct virtio_fpga_afu_dma_map {
    pub(crate) hdr:        virtio_fpga_ctrl_hdr,
    pub(crate) flags:      Le32,
    pub(crate) length:     Le64,
}

unsafe impl ByteValued for virtio_fpga_afu_dma_map {}

#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_fpga_afu_resp_dma_map {
    pub(crate) hdr:        virtio_fpga_ctrl_hdr,
    pub(crate) iova:       Le64,
    pub(crate) pfn:        Le64,
    pub(crate) num_page:   Le64,
}

unsafe impl ByteValued for virtio_fpga_afu_resp_dma_map {}

#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_fpga_afu_dma_unmap {
    pub(crate) hdr:        virtio_fpga_ctrl_hdr,
    pub(crate) iova:       Le64,
}

unsafe impl ByteValued for virtio_fpga_afu_dma_unmap {}

#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_fpga_afu_resp_dma_unmap {
    hdr:        virtio_fpga_ctrl_hdr,
}

unsafe impl ByteValued for virtio_fpga_afu_resp_dma_unmap {}

#[derive(Debug)]
pub enum VirtioFpgaCommandError {
    UnknownCommand(u32),
}

#[derive(Debug, Clone)]
pub enum VirtioFpgaCommand {
    VirtioFpgaAfuPortInfo(virtio_fpga_afu_port_info),
    VirtioFpgaAfuRegionInfo(virtio_fpga_afu_region_info),
    VirtioFpgaAfuDmaMap(virtio_fpga_afu_dma_map),
    VirtioFpgaAfuDmaUnmap(virtio_fpga_afu_dma_unmap),
}

impl VirtioFpgaCommand {
    pub fn decode(
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
    ) -> Result<Self> {
        let hdr = mem.read_obj::<virtio_fpga_ctrl_hdr>(addr)?;

        Ok(match hdr.type_.to_native() {
            VIRTIO_FPGA_CMD_GET_PORT_INFO => VirtioFpgaAfuPortInfo(mem.read_obj(addr)?),
            VIRTIO_FPGA_CMD_GET_PORT_REGION_INFO => VirtioFpgaAfuRegionInfo(mem.read_obj(addr)?),
            VIRTIO_FPGA_CMD_DMA_MAP => VirtioFpgaAfuDmaMap(mem.read_obj(addr)?),
            VIRTIO_FPGA_CMD_DMA_UNMAP => VirtioFpgaAfuDmaUnmap(mem.read_obj(addr)?),
            type_ => return Err(Error::UnknownCommand(type_))
        })
    }
}

unsafe impl ByteValued for virtio_fpga_config{}

#[derive(Debug)]
pub enum VirtioFpgaResponse {
    OkNoData,
    OkPortInfo {
        flags: u32,
        num_regions: u32,
        num_umsgs:   u32,
    },
    OkRegionInfo {
        flags: u32,
        size: u64,
        offset: u64,
    },
    OkDmaMap {
        iova:      u64,
        pfn:       u64,
        num_page:  u64,
    },

    ErrUnspec,
    ErrPortNotExist(u32),
    ErrIovaNotExist,

    // hypervisor define error, used for log
    ErrMemControl(VmMemError),
    ErrMemLock,
    ErrMmap(MmapRegionError),
    ErrVmMem(vm_memory::Error),
}

impl VirtioFpgaResponse {
    pub fn encode(
        &self,
        flags: u32,
        port_id: u32,
        is_fme: bool
    ) -> std::result::Result<Vec<u8>, VirtioFpgaResponse>{
        let mut hdr = virtio_fpga_ctrl_hdr {
            type_: Le32::from(VIRTIO_FPGA_RESP_ERR_UNSPEC),
            flags: Le32::from(flags),
            port_id: Le32::from(port_id),
            is_fme: Le32::from(is_fme as u32),
            padding: Default::default()
        };

        let ans = match self {
            VirtioFpgaResponse::OkNoData => {
                hdr.type_ = Le32::from(VIRTIO_FPGA_RESP_OK_NODATA);
                hdr.as_slice().iter().cloned().collect()
            }
            VirtioFpgaResponse::OkPortInfo {
                flags, num_regions, num_umsgs
            } => {
                hdr.type_ = Le32::from(VIRTIO_FPGA_RESP_OK_PORT_INFO);
                let port_info = virtio_fpga_afu_resp_port_info {
                    hdr,
                    flags: Le32::from(*flags),
                    num_regions: Le32::from(*num_regions),
                    num_umsgs: Le32::from(*num_umsgs),
                };
                port_info.as_slice().iter().cloned().collect()
            }
            VirtioFpgaResponse::OkRegionInfo {
                flags, size, offset
            } => {
                hdr.type_ = Le32::from(VIRTIO_FPGA_RESP_OK_REGION_INFO);
                let region_info = virtio_fpga_afu_resp_region_info {
                    hdr,
                    flags: Le32::from(*flags),
                    padding: Default::default(),
                    size: Le64::from(*size),
                    offset: Le64::from(*offset),
                };
                region_info.as_slice().iter().cloned().collect()
            }
            VirtioFpgaResponse::OkDmaMap { iova, pfn, num_page } => {
                hdr.type_ = Le32::from(VIRTIO_FPGA_RESP_OK_DMA_REGION);
                let dma = virtio_fpga_afu_resp_dma_map {
                    hdr,
                    iova: Le64::from(*iova),
                    pfn: Le64::from(*pfn),
                    num_page:Le64::from(*num_page),
                };

                dma.as_slice().iter().cloned().collect()
            },
            VirtioFpgaResponse::ErrPortNotExist(port_id) => {
                debug!("fpga: vport id {:?} not exist!", port_id);
                hdr.type_ = Le32::from(VIRTIO_FPGA_RESP_ERR_PORT_NOT_EXIST);
                hdr.as_slice().iter().cloned().collect()
            },
            VirtioFpgaResponse::ErrIovaNotExist => {
                debug!("fpga: iova not exist");
                hdr.type_ = Le32::from(VIRTIO_FPGA_RESP_ERR_IOVA_NOT_EIXST);
                hdr.as_slice().iter().cloned().collect()
            },
            VirtioFpgaResponse::ErrMemControl(_)
            | VirtioFpgaResponse::ErrMemLock
            | VirtioFpgaResponse::ErrUnspec
            | VirtioFpgaResponse::ErrMmap(_)
            | VirtioFpgaResponse::ErrVmMem(_) => {
                error!("fpga: mem control failed, err: {:?}", self);
                hdr.type_ = Le32::from(VIRTIO_FPGA_RESP_ERR_UNSPEC);
                hdr.as_slice().iter().cloned().collect()
            }
        };

        Ok(ans)
    }
}