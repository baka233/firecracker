use crate::virtio::{VirtioDevice, ActivateResult, Queue, DeviceState, VIRTIO_MMIO_INT_VRING};
use vm_memory::{GuestMemoryMmap, ByteValued, Le32, Bytes, GuestAddress, Address};
use std::sync::{Arc, Mutex};
use utils::eventfd::EventFd;
use std::sync::atomic::{AtomicUsize, Ordering};

use vhost_gpu_backend::protocol::{VIRTIO_GPU_DEVICE_TYPE, virtio_gpu_config, VIRTIO_GPU_EVENT_DISPLAY, VIRTIO_GPU_F_VIRGL, VIRTIO_GPU_F_RESOURCE_UUID, virtio_gpu_mem_entry, VIRTIO_GPU_FLAG_FENCE};
use vhost_gpu_backend::virtio_gpu::{GpuMode, GpuParameter};
use vhost_gpu_backend::{VirtioGpu, RutabagaFenceData, VirtioGpuResponse, VirtioGpuCommand, VirtioGpuResponseResult};

use logger::{METRICS, IncMetric, warn, error, debug};
use std::io::Write;
use std::cmp::min;

use crate::virtio::gpu::{Error, Result};
use std::collections::{VecDeque};
use crate::virtio::gpu::request::Request;
use crate::virtio::gpu::utils::{sglist_to_rutabaga_iovecs, fence_ctx_equal};
use std::ops::{DerefMut};
use std::mem::size_of;
use std::os::unix::io::AsRawFd;
use polly::event_manager::{EventManager, Subscriber};

pub(crate) struct FenceDescriptor {
    pub(crate) desc_fence: RutabagaFenceData,
    pub(crate) index:      u16,
    pub(crate) len:        u32,
}

pub(crate) struct ReturnDescriptor {
    pub(crate) index:      u16,
    pub(crate) len:        u32,
}

pub struct Gpu {
    pub(crate) queues:           Vec<Queue>,
    pub(crate) interrupt_evt:    EventFd,
    pub(crate) queue_evts:       Vec<EventFd>,
    pub(crate) activate_evt:     EventFd,
    // fence event, write the event to notify we have fenced descriptor to process
    pub(crate) fence_evt:        EventFd,
    pub(crate) fence_descriptors:Vec<FenceDescriptor>,
    // indicates the display is changed
    pub(crate) config_event:     bool,
    pub(crate) waiting_fence:    bool,
    pub(crate) avail_features:   u64,
    pub(crate) acked_features:   u64,
    pub(crate) gpu_mode:         GpuMode,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    pub(crate) virtio_gpu:       Option<Arc<Mutex<VirtioGpu>>>,
    pub(crate) device_status:    DeviceState,
    pub(crate) num_scanout:      u32,
}

pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 2;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

pub const CTRL_QUEUE: usize = 0;
pub const CURSOR_QUEUE: usize = 1;

impl Gpu {
    pub fn new(gpu_mode: GpuMode) -> Result<Self> {
        let mut queue_evts = Vec::new();
        for _ in QUEUE_SIZES.iter() {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?);
        }
        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        let avail_features = match gpu_mode {
            GpuMode::Mode2D => 0,
            GpuMode::Mode3D => {
                1 << VIRTIO_GPU_F_VIRGL
                    | 1 << VIRTIO_GPU_F_RESOURCE_UUID
            }
        };

        Ok(Gpu {
            queues,
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            queue_evts,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            // default to false
            fence_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            fence_descriptors: Vec::new(),
            config_event: false,
            waiting_fence: false,
            avail_features,
            acked_features: 0,
            gpu_mode: GpuMode::Mode3D,
            interrupt_status: Arc::new(Default::default()),
            virtio_gpu: None,
            device_status: DeviceState::Inactive,
            num_scanout: 1,
        })
    }


    pub fn signal_used_queue(&self) -> Result<()> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);

        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            METRICS.gpu.event_fails.inc();
            Error::FailedSignalingUsedQueue(e)
        })?;
        Ok(())
    }

    pub fn id(&self) -> String {
        "gpu".to_string()
    }
    
    pub(crate) fn process_request(virtio_gpu: &mut VirtioGpu, request: &Request, mem: &GuestMemoryMmap) -> VirtioGpuResponseResult {
        // let mut virtio_gpu = self.virtio_gpu.as_ref().unwrap().lock().unwrap();
        virtio_gpu.force_ctx_0();
        match request.command {
            VirtioGpuCommand::CmdGetDisplayInfo(cmd) => {
                virtio_gpu.cmd_get_display_info(cmd)
            }
            VirtioGpuCommand::CmdResourceCreate2D(cmd) => {
                virtio_gpu.cmd_resource_create_2d(cmd)
            }
            VirtioGpuCommand::CmdResourceUnref(cmd) => {
                virtio_gpu.cmd_resource_unref(cmd)
            }
            VirtioGpuCommand::CmdSetScanout(cmd) => {
                virtio_gpu.cmd_set_scanout(cmd)
            }
            VirtioGpuCommand::CmdResourceFlush(cmd) => {
                virtio_gpu.cmd_flush_resource(cmd)
            }
            VirtioGpuCommand::CmdTransferToHost2D(cmd) => {
                virtio_gpu.cmd_transfer_to_host_2d(cmd)
            }
            VirtioGpuCommand::CmdResourceAttachBacking(cmd) => {
                let mut data = Vec::new();
                if request.data_buf.is_none() {
                    return Err(VirtioGpuResponse::ErrInvalidParameter);
                }
                let max_size = cmd.nr_entries.to_native() * size_of::<virtio_gpu_mem_entry>() as u32;
                if request.data_buf.unwrap().1 < max_size {
                    return Err(VirtioGpuResponse::ErrInvalidParameter);
                }

                for i in 0..cmd.nr_entries.to_native() {
                    let addr = request.data_buf
                        .unwrap()
                        .0
                        .unchecked_add(
                            i as u64 * size_of::<virtio_gpu_mem_entry>() as u64
                        );
                    match mem.read_obj::<virtio_gpu_mem_entry>(addr) {
                        Ok(entry) => {
                            let addr = GuestAddress(entry.addr.to_native());
                            let len = entry.length.to_native() as usize;
                            data.push((addr, len));
                        },
                        Err(_) => return Err(VirtioGpuResponse::ErrInvalidParameter),
                    }
                }
                
                let rutabaga_iovecs = sglist_to_rutabaga_iovecs(&data, mem);

                if let Err(_) = rutabaga_iovecs {
                    return Err(VirtioGpuResponse::ErrInvalidParameter);
                }

                virtio_gpu.cmd_resource_attach_backing(cmd, rutabaga_iovecs.unwrap())
            }
            VirtioGpuCommand::CmdResourceAssignUuid(cmd) => {
                virtio_gpu.cmd_resource_assign_uuid(cmd)
            }
            VirtioGpuCommand::CmdResourceDetachBacking(cmd) => {
                virtio_gpu.cmd_resource_detach_backing(cmd)
            }
            VirtioGpuCommand::CmdGetCapsetInfo(cmd) => {
                virtio_gpu.cmd_get_capset_info(cmd)
            }
            VirtioGpuCommand::CmdGetCapset(cmd) => {
                virtio_gpu.cmd_get_capset(cmd)
            }
            VirtioGpuCommand::CmdGetEdid(_) => {
                Err(VirtioGpuResponse::ErrUnspec)
            }
            VirtioGpuCommand::CmdCtxCreate(cmd) => {
                virtio_gpu.cmd_context_create(cmd)
            }
            VirtioGpuCommand::CmdCtxDestroy(cmd) => {
                virtio_gpu.cmd_context_destroy(cmd)
            }
            VirtioGpuCommand::CmdCtxAttachResource(cmd) => {
                virtio_gpu.cmd_ctx_attach_resource(cmd)
            }
            VirtioGpuCommand::CmdCtxDetachResource(cmd) => {
                virtio_gpu.cmd_ctx_detach_resource(cmd)
            }
            VirtioGpuCommand::CmdResourceCreate3D(cmd) => {
                virtio_gpu.cmd_resource_create_3d(cmd)
            }
            VirtioGpuCommand::CmdTransferToHost3D(cmd) => {
                virtio_gpu.cmd_transfer_to_host_3d(cmd)
            }
            VirtioGpuCommand::CmdTransferFromHost3D(cmd) => {
                virtio_gpu.cmd_transfer_from_host_3d(cmd, None)
            }
            VirtioGpuCommand::CmdSubmit3D(cmd) => {
                let mut buf = vec![0; cmd.size.to_native() as usize];
                if request.data_buf.is_none() {
                    return Err(VirtioGpuResponse::ErrInvalidParameter);
                }
                mem.read_slice(buf.as_mut_slice(), request.data_buf.unwrap().0)
                    .map_err(|_| {
                        VirtioGpuResponse::ErrInvalidParameter
                    })?;
                virtio_gpu.cmd_submit_3d(cmd, buf.as_mut_slice())
            }
            VirtioGpuCommand::CmdUpdateCursor(_) => {
                Err(VirtioGpuResponse::ErrUnspec)
            }
            VirtioGpuCommand::CmdMoveCursor(_) => {
                Err(VirtioGpuResponse::ErrUnspec)
            }
        }
    }

    pub fn activate_and_build(&mut self, event_manager: &mut EventManager) {
        if let Err(e) = self.activate_evt.read() {
            error!("Gpu: failed to read event, err: {:?}", e);
            METRICS.gpu.event_fails.inc();
            return;
        };
        let gpu_parameter: GpuParameter = Default::default();
        self.virtio_gpu = Some(Arc::new(
            Mutex::new(VirtioGpu::new(gpu_parameter).map_err(|e| {
                panic!("Gpu: create new virtio gpu failed, err: {:?}", e);
            }).unwrap())));
        if let None = self.virtio_gpu {
            warn!("Gpu: initial VirtioGpu instance failed, gpu_parameter: {:?}", gpu_parameter);
            METRICS.gpu.initial_fails.inc();
        }

        let activate_fd = self.activate_evt.as_raw_fd();
        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let self_subscriber = match event_manager.subscriber(activate_fd) {
            Ok(subscriber) => subscriber,
            Err(e) => {
                error!("Failed to process gpu activate evt: {:?}", e);
                return;
            }
        };

        // Interest list changes when the device is activated.
        let interest_list = self.interest_list();
        for event in interest_list {
            event_manager
                .register(event.data() as i32, event, self_subscriber.clone())
                .unwrap_or_else(|e| {
                    error!("Failed to register gpu events: {:?}", e);
                });
        }

        event_manager.unregister(activate_fd).unwrap_or_else(|e| {
            error!("Failed to unregister gpu activate evt: {:?}", e);
        });
    }

    pub fn process_queue_event(&mut self, queue_type: usize) {
        if let Err(e) = self.queue_evts[queue_type].read() {
            error!("Gpu: failed to read event, err: {:?}", e);
            METRICS.gpu.event_fails.inc();
        } else {
            let any_used = self.process_queue(queue_type);
            if any_used {
                let _ = self.signal_used_queue();
            }
        }
    }

    pub(crate) fn poll_fence(&mut self) {
        let mem = match self.device_status {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => return,
        };


        let completed_fences;

        {
            let mut virtio_gpu = self.virtio_gpu.as_ref().unwrap().lock().unwrap();
            completed_fences = virtio_gpu.fence_poll();
        }

        let mut return_descs = VecDeque::new();

        self.fence_descriptors.retain(|f_desc| {
            for completed in &completed_fences {
                if fence_ctx_equal(&f_desc.desc_fence, completed) {
                    return_descs.push_back(ReturnDescriptor {
                        index: f_desc.index,
                        len: f_desc.len,
                    });
                    return false;
                }
            }
            true
        });

        let mut any_used = false;

        while let Some(desc) = return_descs.pop_front() {
            self.queues[CTRL_QUEUE].add_used(mem, desc.index, desc.len).unwrap_or_else(|e| {
                error!(
                    "Failed to add available descriptor head {}: {}",
                    desc.index, e
                )
            });
            any_used = true;
        }

        if any_used {
            let _ = self.signal_used_queue();
        }

        if self.fence_descriptors.is_empty() {
            self.waiting_fence = false;
            if let Err(e) = self.fence_evt.read() {
                error!("Gpu: read fence evt failed, er: {:?}", e);
                METRICS.gpu.event_fails.inc();
            }
        }

        return;

    }

    fn process_queue(&mut self, queue_type: usize) -> bool {
        let queue = &mut self.queues[queue_type];
        let mem = match self.device_status {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => return false,
        };

        let mut any_used = false;

        while let Some(head) = queue.pop(mem) {
            match Request::parse(&head, mem) {
                Ok(request) => {
                    let response_result;

                    {
                        let mut virtio_gpu = self.virtio_gpu.as_ref().unwrap().lock().unwrap();
                        response_result = Self::process_request(virtio_gpu.deref_mut(), &request, mem);
                    }

                    let flags = request.cmd_hdr.flags.to_native();
                    let fence_id = request.cmd_hdr.fence_id.to_native();
                    let ctx_id = request.cmd_hdr.ctx_id.to_native();


                    let mut response = match response_result {
                        Ok(r) => r,
                        Err(r) => {
                            error!("{:?} -> {:?}", request.command, r);
                            r
                        }
                    };

                    if flags & VIRTIO_GPU_FLAG_FENCE != 0 {
                        let virtio_gpu_result = self.virtio_gpu.as_ref().unwrap().lock();
                        if let Err(_) = virtio_gpu_result {
                            panic!("poisoned lock!");
                        }
                        let mut virtio_gpu = virtio_gpu_result.unwrap();
                        let fence_data = RutabagaFenceData {
                            flags,
                            fence_id,
                            ctx_id,
                            fence_ctx_idx: request.cmd_hdr.padding.to_native(),
                        };
                        response = match virtio_gpu.create_fence(fence_data) {
                            Ok(_) => response,
                            Err(fence_resp) => {
                                warn!("create_fence {} => {:?}", fence_id, fence_resp);
                                fence_resp
                            }
                        }
                    }

                    let encoded_data = response.encode(flags, fence_id, ctx_id);

                    // ignore error
                    if let Err(_) = encoded_data {
                        continue;
                    }

                    let len = encoded_data.as_ref().unwrap().len() as u32;

                    if flags & VIRTIO_GPU_FLAG_FENCE != 0 {
                        self.fence_descriptors.push(FenceDescriptor {
                            desc_fence: RutabagaFenceData {
                                flags,
                                fence_id,
                                ctx_id,
                                fence_ctx_idx: request.cmd_hdr.padding.to_native()
                            },
                            index: request.desc_index,
                            len,
                        })
                    }

                    // it's safe to unwrap, we have already checked
                    let _ = request.write_response(encoded_data.unwrap().as_slice(), mem).map_err(|e| {
                        error!("write response failed, err: {:?}", e);
                        e
                    });

                    // if the request not fenced, just used the queue
                    if flags & VIRTIO_GPU_FLAG_FENCE == 0 {
                        queue.add_used(mem, request.desc_index, len).unwrap_or_else(|e| {
                            error!(
                                "Failed to add available descriptor head {}: {}",
                                head.index, e
                            )
                        });
                        any_used = true;
                    } else {
                        if !self.waiting_fence {
                            self.waiting_fence = true;
                            let _ = self.fence_evt.write(1).map_err(|e| {
                                error!("make fence event failed!, err: {:?}", e);
                                e
                            });
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to parse available descriptor chain: {:?}", e);
                    METRICS.gpu.execute_fails.inc();
                    queue.add_used(mem, head.index, 0).unwrap_or_else(|e| {
                        error!(
                            "Failed to add available descriptor head {}: {}",
                            head.index, e
                        )
                    });
                    any_used = true;
                }
            }


        }

        any_used
    }


    fn get_config(&self) -> virtio_gpu_config {
        let mut events_read = 0;
        if self.config_event {
            events_read |= VIRTIO_GPU_EVENT_DISPLAY;
        }

        let capsets = match self.gpu_mode {
            GpuMode::Mode2D => 0,
            _ => 5,
        };

        virtio_gpu_config {
            events_read:  Le32::from(events_read),
            events_clear: Le32::from(0),
            num_scanouts: Le32::from(self.num_scanout),
            num_capsets:  Le32::from(capsets),
        }
    }

}

impl VirtioDevice for Gpu {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        VIRTIO_GPU_DEVICE_TYPE
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config = self.get_config();
        let bytes = config.as_slice();
        let bytes_len = bytes.len();

        if offset >= bytes_len as u64{
            error!("Failed to read config space");
            METRICS.gpu.event_fails.inc();
            return;
        }

        let data_len = data.len();

        if let Some(end) = offset.checked_add(data_len as u64) {
            // if we can not write config, we will panic.
            data.write_all(
                &bytes[offset as usize..min(end as usize, bytes_len)]
            ).unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let mut config: virtio_gpu_config = Default::default();
        let data_len = data.len();
        if data_len + offset as usize >= config.as_slice().len() {
            error!("failed to write config");
            METRICS.gpu.cfg_fails.inc();
            return;
        }

        let config_slice = config.as_mut_slice();
        config_slice[offset as usize..(data_len + offset as usize)].copy_from_slice(data);

        if config.events_clear.to_native() & VIRTIO_GPU_EVENT_DISPLAY != 0 {
            self.config_event = false;
            METRICS.gpu.display_change.inc();
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        debug!("Gpu: try to activate gpu");
        if self.activate_evt.write(1).is_err() {
            error!("Gpu: Cannot write to activate_evt");
            return Err(super::super::ActivateError::BadActivate);
        }
        self.device_status = DeviceState::Activated(mem);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        match self.device_status {
            DeviceState::Activated(_) => true,
            DeviceState::Inactive => false,
        }
    }
}