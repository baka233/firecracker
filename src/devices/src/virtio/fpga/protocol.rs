use vm_memory::{Le32, ByteValued};

pub const VIRTIO_FPGA_DEVICE_TYPE: u32 = 100;

pub const VIRTIO_FPGA_F_VFME: u64 = 0;

#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_fpga_config {
    pub port_num:       Le32,
}

unsafe impl ByteValued for virtio_fpga_config{}