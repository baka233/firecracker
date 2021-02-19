use std::{cmp, fmt};
use std::collections::{HashMap, BTreeSet};
use std::fmt::Formatter;

#[derive(Debug)]
pub enum Error {
    AllocSizeZero,
    PoolSizeZero,
    PoolOverflow {
        base: u64,
        size: u64,
    },
    BadAlignment,
    BadAlloc(Alloc),
    ExistAlloc(Alloc),
    OutOfSpace,
    RegionOverlap {
        base: u64,
        size: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::AllocSizeZero => write!(f, "allocate size is zero") ,
            Error::PoolSizeZero => write!(f, "pool size is zero"),
            Error::PoolOverflow { base, size } =>  write!(f, "pool size overflow, base: {}, size: {}", base, size),
            Error::BadAlignment => write!(f, "bad alignment"),
            Error::BadAlloc(alloc) => write!(f, "alloc {:?} is not valid", alloc),
            Error::ExistAlloc(alloc) => write!(f, "alloc {:?} is already exist", alloc),
            Error::OutOfSpace => write!(f, "out of space"),
            Error::RegionOverlap { base, size } => write!(f, "region overlap, base: {}, size: {}", base, size)
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// Alloc enum for identify the memory region
#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone)]
pub enum Alloc {
    /// Fpga MMIO map region
    FpgaMMIOMap(u32),
    /// Fpga dma map region
    FpgaDmaBuffer((u32, u32)),
}


pub struct AddressAllocator {
    alignment: u64,
    allocs:    HashMap<Alloc, (u64, u64, String)>,
    regions:   BTreeSet<(u64, u64)>
}

impl AddressAllocator {
    pub fn new(pool_base: u64, pool_size: u64, align_size: Option<u64>) -> Result<Self> {
        if pool_size == 0 {
            return Err(Error::PoolSizeZero);
        }
        let pool_end = pool_base
            .checked_add(pool_size - 1)
            .ok_or(Error::PoolOverflow {
                base: pool_base,
                size: pool_size,
            })?;
        let alignment = align_size.unwrap_or(0);
        if !alignment.is_power_of_two() || alignment == 0 {
            return Err(Error::BadAlignment);
        }
        let mut regions = BTreeSet::new();
        regions.insert((pool_size, pool_end));
        Ok(AddressAllocator {
            alignment,
            allocs: HashMap::new(),
            regions,
        })
    }

    pub fn allocate(
        &mut self,
        size: u64,
        alloc: Alloc,
        tag: String,
    ) -> Result<u64> {
        self.allocate_with_align(size, alloc, tag, self.alignment)
    }

    pub fn allocate_with_align(
        &mut self,
        size:  u64,
        alloc: Alloc,
        tag:   String,
        alignment: u64,
    ) -> Result<u64> {
        let alignment = cmp::max(self.alignment, alignment);

        if self.allocs.contains_key(&alloc) {
            return Err(Error::ExistAlloc(alloc)) ;
        }

        if size == 0 {
            return Err(Error::AllocSizeZero);
        }

        if !alignment.is_power_of_two() {
            return Err(Error::BadAlignment);
        }

        match self
            .regions
            .iter()
            .find(|range| {
                match range.0 % alignment {
                    0 => range.0.checked_add(size - 1),
                    r => range.0.checked_add(size - 1 + alignment - r)
                }.map_or(false, |end| end < range.1)
            })
            .cloned()
        {
            Some(slot) => {
                self.regions.remove(&slot);
                let start = match slot.0 % alignment {
                    0 => slot.0,
                    r => slot.0 + alignment - r
                };
                let end = start + size - 1;
                if slot.0 < start {
                    self.regions.insert((slot.0, start - 1));
                }
                if slot.1 > end {
                    self.regions.insert((end + 1, slot.1));
                }
                self.allocs.insert(alloc, (start, end, tag));
                Ok(start)
            },
            None => Err(Error::OutOfSpace),
        }
    }

    /// release alloc
    pub fn release(&mut self, alloc: Alloc) -> Result<()> {
        self.allocs
            .remove(&alloc)
            .map_or_else(|| Err(Error::BadAlloc(alloc)), |v| self.insert_at(v.0, v.1))
    }

    /// Insert range of addresses into the pool, coalescing neighboring regions.
    fn insert_at(&mut self, start: u64, size: u64) -> Result<()> {
        if size == 0 {
            return Err(Error::AllocSizeZero);
        }

        let mut slot = (start, start.checked_add(size - 1).ok_or(Error::OutOfSpace)?);
        let mut left = None;
        let mut right = None;
        // simple coalescing with linear search over free regions.
        //
        // Calculating the distance between start and end of two regions we can
        // detect if they are disjoint (>1), adjacent (=1) or possibly
        // overlapping (<1). Saturating arithmetic is used to avoid overflow.
        // Overlapping regions are detected if both oposite ends are overlapping.
        // Algorithm assumes all existing regions are disjoined and represented
        // as pair of inclusive location point (start, end), where end >= start.
        for range in self.regions.iter() {
            match (
                slot.0.saturating_sub(range.1),
                range.0.saturating_sub(slot.1),
            ) {
                (1, 0) => {
                    left = Some(*range);
                }
                (0, 1) => {
                    right = Some(*range);
                }
                (0, 0) => {
                    return Err(Error::RegionOverlap { base: start, size });
                }
                (_, _) => (),
            }
        }
        if let Some(left) = left {
            self.regions.remove(&left);
            slot.0 = left.0;
        }
        if let Some(right) = right {
            self.regions.remove(&right);
            slot.1 = right.1;
        }
        self.regions.insert(slot);

        Ok(())
    }
}
