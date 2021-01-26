use crate::request::Body;
use crate::parsed_request::ParsedRequest;
use crate::parsed_request::Error;
use logger::{METRICS, IncMetric};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::gpu::GpuDeviceConfig;

pub(crate) fn parse_put_gpu(
    _body: &Body
) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.gpu_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::InsertGpuDevice(GpuDeviceConfig{})))
}