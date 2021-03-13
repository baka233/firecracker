use crate::virtio::fpga::protocol::{VirtioFpgaCommand, virtio_fpga_ctrl_hdr};
use vm_memory::{GuestAddress, Bytes, GuestMemoryMmap};
use crate::virtio::DescriptorChain;
use crate::virtio::fpga::{Result, Error};

#[allow(unused)]
pub(crate) struct Request {
    pub(crate) cmd_hdr:    virtio_fpga_ctrl_hdr,
    pub(crate) desc_index: u16,
    pub(crate) command:    VirtioFpgaCommand,
    pub(crate) _cmd_buf:   (GuestAddress, u32),
    pub(crate) data_buf:   Option<(GuestAddress, u32)>,
    pub(crate) resp_buf:   (GuestAddress, u32),
}

impl Request {
    pub fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap
    ) -> Result<Request> {
        if avail_desc.is_write_only() {
            return Err(Error::InvalidDescriptor);
        }

        if !avail_desc.has_next() {
            return Err(Error::InvalidDescriptor);
        }

        let cmd_buf = (avail_desc.addr, avail_desc.len);
        let mut data_buf = None;

        // it's safe to unwrap because we have already checked
        let mut desc = avail_desc.next_descriptor().unwrap();
        if !desc.is_write_only() {
            data_buf = Some((desc.addr, desc.len));
            desc = desc.next_descriptor().unwrap();
        }

        // double check the last desc is write only
        if !desc.is_write_only() {
            return Err(Error::InvalidDescriptor);
        }
        let resp_buf = (desc.addr, desc.len);

        let command = VirtioFpgaCommand::decode(mem, cmd_buf.0)?;
        let cmd_hdr = mem.read_obj::<virtio_fpga_ctrl_hdr>(cmd_buf.0)
            .map_err(Error::GuestMemoryFailed)?;

        Ok(Request {
            cmd_hdr,
            desc_index: avail_desc.index,
            command,
            _cmd_buf: cmd_buf,
            data_buf,
            resp_buf,
        })
    }

    pub fn write_response(&self, data: &[u8], mem: &GuestMemoryMmap) -> Result<()> {
        if (self.resp_buf.1 as usize) < data.len() {
            return Err(Error::InvalidResponse);
        }
        mem.write(data, self.resp_buf.0).map_err(Error::GuestMemoryFailed)?;
        Ok(())
    }
}