use crate::virtio::{VirtioDevice, ActivateResult, Queue, DeviceState, VIRTIO_MMIO_INT_VRING, ActivateError};
use vm_memory::{GuestMemoryMmap, ByteValued, Le32};
use std::sync::{Arc, Mutex};
use utils::eventfd::EventFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use crate::virtio::fpga::protocol::virtio_fpga_config;
use std::io::Write;
use std::cmp::min;
use crate::virtio::fpga::{Result, Error};
use polly::event_manager::{EventManager, Subscriber};
use logger::{METRICS, IncMetric, error, debug};
use crate::virtio::fpga::protocol::*;
use std::os::unix::io::AsRawFd;
use mem_control::MemRequest;
use crate::virtio::fpga::request::Request;
use crate::virtio::fpga::virtio_fpga::VirtioFpga;
use std::ops::DerefMut;

pub enum FpgaDeviceType {
    Afu(u32),
    Fme,
}

pub struct Fpga {
    pub(crate) fme_path:         Option<String>,
    pub(crate) port_paths:       Vec<String>,
    pub(crate) virtio_fpga:      Option<Arc<Mutex<VirtioFpga>>>,
    pub(crate) port_num:         u32,
    pub(crate) avail_features:   u64,
    pub(crate) acked_feature:    u64,
    pub(crate) activate_evt:     EventFd,
    pub(crate) interrupt_evt:    EventFd,
    pub(crate) interrupt_stauts: Arc<AtomicUsize>,
    pub(crate) device_status:    DeviceState,
    pub(crate) queue_evts:       Vec<EventFd>,
    pub(crate) queues:           Vec<Queue>,
    pub(crate) mem_control:      Option<Arc<Mutex<dyn MemRequest + Send>>>,
}

pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 1;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

pub const CTRL_QUEUE: usize = 0;

impl Fpga {
    pub fn new(fme_path: Option<&String>, port_paths: Vec<String>) -> Result<Self> {
        let mut queue_evts = Vec::new();
        for _ in QUEUE_SIZES.iter() {
            queue_evts.push(
                EventFd::new(libc::EFD_NONBLOCK)
                    .map_err(Error::EventFd)?
            );
        }
        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        let avail_features = 1 << VIRTIO_FPGA_F_VFME;

        let port_num = port_paths.len() as u32;

        Ok(Fpga {
            fme_path: fme_path.cloned(),
            port_paths,
            virtio_fpga: None,
            port_num,
            avail_features,
            acked_feature:    0,
            activate_evt:     EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            interrupt_evt:    EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            interrupt_stauts: Arc::new(Default::default()),
            device_status:    DeviceState::Inactive,
            queue_evts,
            queues,
            mem_control: None
        })
    }

    pub(crate) fn activate_and_build(&mut self, event_manager: &mut EventManager) {
        if let Err(e) = self.activate_evt.read() {
            error!("Fpga: failed to read event, err: {:?}", e);
            METRICS.fpga.event_fails.inc();
            return;
        }

        let activate_fd = self.activate_evt.as_raw_fd();
        let self_subscriber = match event_manager.subscriber(activate_fd) {
            Ok(subscriber) => subscriber,
            Err(e) => {
                error!("Failed to process fpga activate evt: {:?}", e);
                return;
            }
        };

        let interest_list = self.interest_list();
        for event in interest_list {
            event_manager
                .register(event.data() as i32, event, self_subscriber.clone())
                .unwrap_or_else(|e| {
                    error!("Failed to register fpga events: {:?}", e);
                });
        }

        event_manager.unregister(activate_fd).unwrap_or_else(|err| {
            error!("Failed to unregister fpga activate evt: {:?}", err);
        });
    }

    pub fn set_vmm(&mut self, vmm: Arc<Mutex<dyn MemRequest + Send>>) {
        self.mem_control = Some(vmm);
    }

    pub fn id(&self) -> String {
        "0".to_string()
    }

    pub fn signal_used_queue(&self) -> Result<()> {
        self.interrupt_status()
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);

        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            METRICS.fpga.event_fails.inc();
            Error::FailedSignalingUsedQueue(e)
        })?;
        Ok(())
    }

    pub(crate) fn process_queue_event(&mut self, queue_type: usize) {
        if let Err(e) = self.queue_evts[queue_type].read() {
            error!("Fpga: failed to read event, err: {:?}", e);
            METRICS.fpga.event_fails.inc();
        } else {
            let any_used = self.process_queue(queue_type);
            if any_used {
                let _ = self.signal_used_queue();
            }
        }
    }

    pub(crate) fn process_request(
        virtio_fpga: &mut VirtioFpga,
        hdr: &virtio_fpga_ctrl_hdr,
        device_type: FpgaDeviceType,
        command: &VirtioFpgaCommand
    ) -> std::result::Result<VirtioFpgaResponse, VirtioFpgaResponse> {
        match device_type {
            FpgaDeviceType::Afu(port_id) => virtio_fpga
                .process_afu_request(port_id, command),
            FpgaDeviceType::Fme => virtio_fpga
                .process_fme_request(command),
        }
    }

    /// process queue, return bool to identify whether notify the guest
    fn process_queue(&mut self, queue_type: usize) -> bool {
        let queue = &mut self.queues[queue_type];
        let mem = match self.device_status {
            DeviceState::Inactive => return false,
            DeviceState::Activated(ref mem) => mem
        };

        let mut any_used = false;

        while let Some(head) = queue.pop(mem) {
            match Request::parse(&head, mem) {
                Ok(request) => {
                    let command = &request.command;
                    let hdr = request.cmd_hdr;
                    let flags = hdr.flags.to_native();
                    let port_id = hdr.port_id.to_native();
                    let is_fme = hdr.is_fme.to_native() != 0;
                    let type_ = if is_fme {
                        FpgaDeviceType::Fme
                    } else {
                        FpgaDeviceType::Afu(hdr.port_id.to_native())
                    };

                    let resp;
                    {
                        let mut virtio_fpga = self.virtio_fpga.as_ref().unwrap().lock().unwrap();
                        resp = Self::process_request(virtio_fpga.deref_mut(), &hdr, type_, command);
                    }


                    let resp = match resp {
                        Ok(r) => r,
                        Err(e) => {
                            debug!("fpga: request failed, {:?} -> {:?}", command, e);
                            e
                        }
                    };

                    let encoded_resp = match resp.encode(flags, port_id, is_fme) {
                        Ok(r) => r,
                        Err(e) => {
                            error!("fpga: resp encode failed, err: {:?}", e);
                            VirtioFpgaResponse::ErrUnspec.encode(
                                flags,
                                port_id,
                                is_fme,
                            ).unwrap()
                        }
                    };
                    let len = encoded_resp.len() as u32;

                    any_used = true;
                    // it's safe to unwrap. if the process failed, we can not do anything
                    let _ = request.write_response(encoded_resp.as_slice(), &mem)
                        .map_err(|e| {
                            error!("fpga: write response failed, err: {:?}", encoded_resp);
                            e
                        });

                    queue.add_used(mem, request.desc_index, len).unwrap_or_else(|e| {
                        error!(
                            "Failed to add available descriptor head {}: {}",
                            head.index, e
                        )
                    });
                },
                Err(e) => {
                    error!("fpga: Failed to parse available descriptor chain: {:?}", e);
                    METRICS.fpga.execute_fails.inc();
                    queue.add_used(mem, head.index, 0).unwrap_or_else(|e| {
                        error!(
                            "fpga: Failed to add available descriptor head {}: {}",
                            head.index, e
                        )
                    });
                    any_used = true;
                }
            };

        }

        return any_used;
    }

    fn get_config(&self) -> virtio_fpga_config {
        virtio_fpga_config {
            port_num: Le32::from(self.port_num),
        }
    }
}

impl VirtioDevice for Fpga {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_feature
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_feature = acked_features
    }

    fn device_type(&self) -> u32 {
        VIRTIO_FPGA_DEVICE_TYPE
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
        self.interrupt_stauts.clone()
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config = self.get_config();
        let bytes = config.as_slice();
        let bytes_len = bytes.len();

        if offset >= bytes_len as u64 {
            error!("Failed to read config space");
            METRICS.fpga.event_fails.inc();
            return;
        }

        let data_len = data.len();

        if let Some(end) = offset.checked_add(data_len as u64) {
            data.write_all(
                &bytes[offset as usize..min(end as usize, bytes_len)]
            ).unwrap();
        }

    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let mut config: virtio_fpga_config = Default::default();
        let data_len = data.len();
        if data_len + offset as usize >= config.as_slice().len() {
            error!("failed to write config");
            METRICS.fpga.cfg_fails.inc();
            return;
        }

        let config_slice = config.as_mut_slice();
        config_slice[offset as usize..(data_len + offset as usize)].copy_from_slice(data);
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        debug!("Fpga: try to activate fpga");
        self.device_status = DeviceState::Activated(mem);
        self.virtio_fpga = Some(Arc::new(Mutex::new(
                VirtioFpga::new(
                self.fme_path.clone(),
                &self.port_paths,
                self.mem_control
                    .as_ref()
                    .ok_or(ActivateError::BadActivate)?
                    .clone()
                )
                .map_err(|_| ActivateError::BadActivate)?
        )));

        if self.activate_evt.write(1).is_err() {
            error!("Fpga: Cannot write to activate_evt");
            return Err(super::super::ActivateError::BadActivate);
        }
        Ok(())
    }

    fn is_activated(&self) -> bool {
        match self.device_status {
            DeviceState::Activated(_) => true,
            DeviceState::Inactive => false,
        }
    }
}