use crate::request::Body;
use crate::parsed_request::ParsedRequest;
use crate::parsed_request::Error;
use logger::{METRICS, IncMetric};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::fpga::FpgaDeviceConfig;

pub(crate) fn parse_put_fpga(
    body: &Body
) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.fpga_count.inc();
    let config = serde_json::from_slice::<FpgaDeviceConfig>(body.raw()).map_err(|err| {
        METRICS.put_api_requests.fpga_fails.inc();
        Error::SerdeJson(err)
    })?;
    Ok(ParsedRequest::new_sync(VmmAction::InsertFpgaDevice(config)))
}