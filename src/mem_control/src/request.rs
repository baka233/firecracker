use crate::address_allocator::Alloc;
use vm_memory::{GuestRegionMmap};
use std::sync::Arc;

/// process memory request
#[derive(Debug)]
pub enum VmMemRequest {
    MemoryAllocate(Alloc, u64, String),
    SetKvmUserMem(Arc<GuestRegionMmap>),
    UnsetKvmUserMem(u32),
    MemoryRelease(Alloc),
}

#[derive(Debug)]
pub enum VmMemResponse {
    /// request process successully
    Success,
    /// memory allocate successfully with
    MemoryAllocate(u64, u64),
    /// map kvm user memory successfully and return slot
    KvmUserMemMapped(u32),
}

#[derive(Debug)]
pub enum VmMemError {
    AllocatorNotExist,
    AddMemRegionFailed,
    RemoveMemRegionFailed,
    SetKvmUserMemFailed,
    UnsetKvmUserMemFailed,
}

pub trait MemRequest {
    fn execute_vm_mem_request(&mut self, request: VmMemRequest)
        -> std::result::Result<VmMemResponse, VmMemError>;
}

