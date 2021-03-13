use std::io;
use vm_memory::GuestMemoryError;

pub mod device;
pub mod event_handler;
mod request;
mod protocol;
mod virtio_fpga;
mod afu;
mod fme;
mod utils;


#[derive(Debug)]
pub enum Error {
    /// EventFd error
    EventFd(io::Error),
    /// IO error
    IO(io::Error),
    /// Invalid Descriptor
    InvalidDescriptor,
    /// Invalid Response[
    InvalidResponse,
    /// Unknown Command
    UnknownCommand(u32),
    /// mem controller not exist
    MemControllerNotExist,
    /// Port id parsed error
    PortIdParse,
    /// Open afu fd
    OpenAfu,
    /// failed signal used queue
    FailedSignalingUsedQueue(std::io::Error),
    /// Guest memory read write failed
    GuestMemoryFailed(GuestMemoryError),
}

impl From<GuestMemoryError> for Error {
    fn from(e: GuestMemoryError) -> Self {
        Error::GuestMemoryFailed(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
