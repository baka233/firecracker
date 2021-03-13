use vm_memory::{GuestAddress, Address};

const PAGE_SIZE: u64 = 0x1000;

pub fn generate_pfn(addr: GuestAddress, len: u64) -> (u64, u64) {
    (addr.raw_value() / PAGE_SIZE, (len + PAGE_SIZE) / PAGE_SIZE)
}