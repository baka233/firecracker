use crate::virtio::DescriptorChain;
use crate::virtio::gpu::{Result, Error};
use vm_memory::{GuestAddress, GuestMemoryMmap, Bytes, Address, ByteValued, MemoryRegionAddress};
use crate::virtio::gpu::Error::InvalidDescriptor;
use std::io::{ErrorKind};
use std::cmp::min;
use logger::info;
use vhost_gpu_backend::VirtioGpuCommand;
use vhost_gpu_backend::protocol::virtio_gpu_ctrl_hdr;
use crate::virtio::gpu::utils::decode_gpu_cmd;

pub(crate) struct Request {
    pub(crate) cmd_hdr:    virtio_gpu_ctrl_hdr,
    pub(crate) desc_index: u16,
    pub(crate) command:    VirtioGpuCommand,
    pub(crate) cmd_buf:    (GuestAddress, u32),
    pub(crate) data_buf:   Option<(GuestAddress, u32)>,
    pub(crate) resp_buf:   (GuestAddress, u32),
}

impl Request {
    pub fn parse(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap
    ) -> Result<Request> {
        if avail_desc.is_write_only() {
            return Err(InvalidDescriptor);
        }

        if !avail_desc.has_next() {
            return Err(InvalidDescriptor);
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
            return Err(InvalidDescriptor);
        }
        let resp_buf = (desc.addr, desc.len);

        let command = decode_gpu_cmd(mem, cmd_buf.0)?;
        let cmd_hdr = mem.read_obj::<virtio_gpu_ctrl_hdr>(cmd_buf.0)
            .map_err(Error::GuestMemoryFailed)?;

        Ok(Request {
            cmd_hdr,
            desc_index: avail_desc.index,
            command,
            cmd_buf,
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


// impl<'a> std::io::Write for Request<'a> {
//     fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//         if self.write_avail < buf.len() {
//             return Err(std::io::Error::from(ErrorKind::InvalidData));
//         }
//
//         let buf_len = buf.len();
//         let mut wrote_len = 0;
//         let (mut start_index, mut start_byte) = self.write_pointer;
//         while buf_len != 0 {
//             let write_len = min(buf_len, self.output_buffers[start_index].1 - start_byte);
//             self.mem.write(
//                 &buf[wrote_len..(wrote_len + write_len)],
//                 self.output_buffers[start_index].0
//                     .unchecked_add(start_byte as u64)
//                 ).map_err(|e| std::io::Error::new(ErrorKind::UnexpectedEof, e))?;
//             wrote_len += write_len;
//             if start_byte + write_len >= self.output_buffers[start_index].1 {
//                 start_byte = 0;
//                 start_index += 1;
//             }
//         }
//
//         self.write_avail -= buf.len();
//         self.write_pointer = (start_index, start_byte);
//
//         Ok(buf.len())
//     }
//
//     /// we don't need flush
//     fn flush(&mut self) -> std::io::Result<()> {
//         return Ok(())
//     }
// }


// impl<'a> std::io::Read for Request<'a> {
//     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//         let buf_len = buf.len();
//         let mut readed_len = 0;
//         let (mut start_index, mut start_byte) = self.read_pointer;
//         while buf_len != 0 {
//             let read_len = min(buf_len, self.input_buffers[start_index].1 - start_byte);
//             self.mem.read(
//                 &mut buf[readed_len..(read_len + readed_len)],
//                 self.input_buffers[start_index].0
//                     .unchecked_add(start_byte as u64)
//                 )
//                 .map_err(|e| std::io::Error::new(ErrorKind::UnexpectedEof, e))?;
//             readed_len += read_len;
//             if start_byte + read_len >= self.input_buffers[start_index].1 {
//                 start_byte = 0;
//                 start_index += 1;
//             }
//         }
//
//         self.read_avail -= buf.len();
//         self.read_pointer = (start_index, start_byte);
//
//         Ok(buf.len())
//     }
// }


#[cfg(test)]
pub(crate) mod tests {
    use vm_memory::{GuestMemoryMmap, GuestAddress, Bytes, Le32, Le64, ByteValued};
    use crate::virtio::test_utils::VirtQueue;
    use vhost_gpu_backend::protocol::{virtio_gpu_ctrl_hdr, VIRTIO_GPU_CMD_GET_DISPLAY_INFO};
    use virtio_gen::virtio_ring::INT_LEAST32_MAX;
    use crate::virtio::gpu::request::Request;
    use vhost_gpu_backend::{VirtioGpuCommand, VirtioGpuResponse};
    use crate::virtio::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::virtio::gpu::Error;

    #[test]
    fn test_write_request() {
        let m = &GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let vq = VirtQueue::new(GuestAddress(0), &m, 16);

        assert!(vq.end().0 < 0x1000);

        let request_descriptor = 0;

        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);


        let mut header_set = virtio_gpu_ctrl_hdr {
            type_: Le32::from(VIRTIO_GPU_CMD_GET_DISPLAY_INFO),
            flags: Le32::from(0),
            fence_id: Le64::from(0),
            ctx_id: Le32::from(0),
            padding: Le32::from(0),
        };

        // test read command
        {
            let resp_descriptor = 1;
            let mut q = vq.create_queue();
            // Write only request type descriptor.
            vq.dtable[request_descriptor].set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable[resp_descriptor].set(0x2000, 0x1000, VIRTQ_DESC_F_WRITE, 2);

            header_set.type_ = Le32::from(VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
            m.write_obj::<virtio_gpu_ctrl_hdr>(header_set, GuestAddress(0x1000))
                .unwrap();
            let request = Request::parse(&q.pop(m).unwrap(), m).unwrap();
            if let VirtioGpuCommand::CmdGetDisplayInfo(hdr) = request.command  {
                assert_eq!(hdr.as_slice(), header_set.as_slice());
            } else {
                panic!();
            }
        }

        // test wrong descriptor chain
        {
            let resp_descriptor = 1;
            let mut q = vq.create_queue();
            // Write only request type descriptor.
            vq.dtable[request_descriptor].set(0x1000, 0x1000, 0, 1);
            vq.dtable[resp_descriptor].set(0x2000, 0x1000, VIRTQ_DESC_F_WRITE, 2);

            header_set.type_ = Le32::from(VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
            m.write_obj::<virtio_gpu_ctrl_hdr>(header_set, GuestAddress(0x1000))
                .unwrap();
            let request = Request::parse(&q.pop(m).unwrap(), m);
            match request {
                Ok(_) => panic!("unexpected parsed successfully!"),
                Err(Error::InvalidDescriptor) => (),
                Err(e) => panic!("unexpected err: {:?}", e),
            }
        }

        // write response
        {
            let resp_descriptor = 1;
            let mut q = vq.create_queue();
            // Write only request type descriptor.
            vq.dtable[request_descriptor].set(0x1000, 0x1000, VIRTQ_DESC_F_NEXT, 1);
            vq.dtable[resp_descriptor].set(0x2000, 0x1000, VIRTQ_DESC_F_WRITE, 2);

            header_set.type_ = Le32::from(VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
            m.write_obj::<virtio_gpu_ctrl_hdr>(header_set, GuestAddress(0x1000))
                .unwrap();
            let request = Request::parse(&q.pop(m).unwrap(), m).unwrap();
            let response = VirtioGpuResponse::encode(&VirtioGpuResponse::OkDisplayInfo(
                    vec![(1920, 1080)]
                ), 0, 0, 0).unwrap();

            request.write_response(response.as_slice(), m).unwrap();
        }

    }
}