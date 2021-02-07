use crate::virtio::fpga::device::{Fpga, CTRL_QUEUE};
use polly::event_manager::{Subscriber, EventManager};
use utils::epoll::{EpollEvent, EventSet};
use crate::virtio::{VirtioDevice};
use logger::{METRICS, warn, IncMetric};

use std::os::unix::io::AsRawFd;

impl Subscriber for Fpga {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let event_set = event.event_set();

        let supported_event = EventSet::IN;

        if !supported_event.contains(event_set) {
            warn!(
                "Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        let virtio_ctrl_queue = self.queue_evts[CTRL_QUEUE].as_raw_fd();
        let activate_fd = self.activate_evt.as_raw_fd();

        if self.is_activated() {
            match source {
                _ if source == virtio_ctrl_queue => self.process_queue_event(CTRL_QUEUE),
                _ if source == activate_fd => self.activate_and_build(event_manager),
                _ => {
                    warn!(
                        "Fpga: Spurious event received, {:?}",
                        source
                    );
                    METRICS.fpga.event_fails.inc();
                }
            }
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        if self.is_activated() {
            vec![
                EpollEvent::new(EventSet::IN, self.queue_evts[CTRL_QUEUE].as_raw_fd() as u64),
            ]
        } else {
            vec![
                EpollEvent::new(EventSet::IN, self.activate_evt.as_raw_fd() as u64),
            ]
        }
    }
}