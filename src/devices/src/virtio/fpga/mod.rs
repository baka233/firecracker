use std::io;

pub mod device;
pub mod event_handler;
mod protocol;


#[derive(Debug)]
pub enum Error {
    /// EventFd error
    EventFd(io::Error),
    // IO error
    IO(io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
