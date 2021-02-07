use crate::virtio::{VirtioDevice, ActivateResult, Queue, DeviceState};
use vm_memory::{GuestMemoryMmap, ByteValued, Le32};
use std::sync::Arc;
use utils::eventfd::EventFd;
use std::sync::atomic::AtomicUsize;
use crate::virtio::fpga::protocol::virtio_fpga_config;
use std::io::Write;
use std::cmp::min;
use crate::virtio::fpga::{Result, Error};
use polly::event_manager::{EventManager, Subscriber};
use logger::{METRICS, IncMetric, warn, error, debug};
use crate::virtio::fpga::protocol::*;
use std::os::unix::io::AsRawFd;

pub struct Fpga {
    pub(crate) fme_path:         String,
    pub(crate) port_paths:       Vec<String>,
    pub(crate) port_num:         u32,
    pub(crate) avail_features:    u64,
    pub(crate) acked_feature:    u64,
    pub(crate) activate_evt:     EventFd,
    pub(crate) interrupt_evt:    EventFd,
    pub(crate) interrupt_stauts: Arc<AtomicUsize>,
    pub(crate) device_status:    DeviceState,
    pub(crate) queue_evts:       Vec<EventFd>,
    pub(crate) queues:           Vec<Queue>,
}

pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 1;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

pub const CTRL_QUEUE: usize = 0;

impl Fpga {
    pub fn new(fme_path: String, port_paths: Vec<String>) -> Result<Self> {
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
            fme_path,
            port_paths,
            port_num,
            avail_features,
            acked_feature:    0,
            activate_evt:     EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            interrupt_evt:    EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            interrupt_stauts: Arc::new(Default::default()),
            device_status:    DeviceState::Inactive,
            queue_evts,
            queues
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

    pub fn id(&self) -> String {
        "0".to_string()
    }

    pub(crate) fn process_queue_event(&mut self, queue_type: usize) {
        if let Err(e) = self.queue_evts[queue_type].read() {
            error!("Fpga: failed to read event, err: {:?}", e);
            METRICS.fpga.event_fails.inc();
        } else {
            warn!("Fpga: unimplement process request");
        }
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
        if self.activate_evt.write(1).is_err() {
            error!("Fpga: Cannot write to activate_evt");
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