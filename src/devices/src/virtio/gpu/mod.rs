use std::io;
use vhost_gpu_backend::{VirtioGpuCommandDecodeError, VirtioGpuResponse};
use crate::virtio::gpu::Error::{CmdDecodeFailed, ResponseError};
use vm_memory::GuestMemoryError;

pub mod device;
pub mod event_handler;
pub mod request;
mod utils;

pub use vhost_gpu_backend::virtio_gpu::GpuMode;

#[derive(Debug)]
pub enum Error {
    /// EventFd error.
    EventFd(io::Error),
    /// IO error.
    IO(io::Error),
    /// Gpu build failed error.
    GpuBuildFailed,
    /// Invalid avail descriptor
    InvalidDescriptor,
    /// Command decode error
    CmdDecodeFailed(VirtioGpuCommandDecodeError),
    /// Failed to signal used queue
    FailedSignalingUsedQueue(std::io::Error),
    /// Guest memory error
    GuestMemoryFailed(GuestMemoryError),
    /// IvalidResponse
    InvalidResponse,
    /// VirtioResponseError
    ResponseError(VirtioGpuResponse),
    /// invalid sglist region
    InvalidSglistRegion,
}

impl From<VirtioGpuCommandDecodeError> for Error {
    fn from(e: VirtioGpuCommandDecodeError) -> Self {
        CmdDecodeFailed(e)
    }
}

impl From<VirtioGpuResponse> for Error {
    fn from(r: VirtioGpuResponse) -> Self {
        ResponseError(r)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
