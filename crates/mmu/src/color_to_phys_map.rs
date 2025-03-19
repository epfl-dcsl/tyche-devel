use core::{mem, slice};

use utils::{HostPhysAddr, HostVirtAddr};

use crate::frame_allocator::PhysRange;
use crate::memory_painter::{MemoryColoring, MemoryRegion, MemoryRegionKind};

pub struct ColorToPhysMap<'a> {
    /// base pointer to memory range
    raw_base_ptr: *mut u8,
    /// size of base memory range
    bytes: usize,
    /// 2D color to ranges arrays as flat array with fixed size per sub array
    ranges: &'a mut [PhysRange],
    /// Length of each sub array in `ranges`
    entries_per_color: usize,
    /// ranges to the next unused entrie for each subarray in ranges
    ranges_next_idx: &'a mut [usize],
    /// color to exact number of bytes per range array
    exact_sizes: &'a mut [u64],
}

impl<'a> ColorToPhysMap<'a> {
    pub fn deserialize(
        raw_base_ptr: u64,
        bytes: u64,
        entries_per_color: usize,
        color_count: usize,
    ) -> Self {
        let raw_base_ptr = raw_base_ptr as *mut u8;
        let (ranges, ranges_next_idx, exact_sizes) =
            Self::cust_mem_into_slices(raw_base_ptr, color_count, entries_per_color);

        Self {
            raw_base_ptr,
            bytes: bytes as usize,
            ranges,
            exact_sizes,
            ranges_next_idx,
            entries_per_color,
        }
    }

    fn cust_mem_into_slices(
        raw_mem_ptr: *mut u8,
        color_count: usize,
        entries_per_color: usize,
    ) -> (&'a mut [PhysRange], &'a mut [usize], &'a mut [u64]) {
        let exact_sizes =
            unsafe { slice::from_raw_parts_mut(raw_mem_ptr as *mut u64, color_count) };
        let mut byte_offset = (exact_sizes.len() * mem::size_of::<u64>()) as isize;

        let ranges_next_idx = unsafe {
            slice::from_raw_parts_mut(raw_mem_ptr.offset(byte_offset) as *mut usize, color_count)
        };
        byte_offset += (ranges_next_idx.len() * mem::size_of::<usize>()) as isize;

        let ranges = unsafe {
            slice::from_raw_parts_mut(
                raw_mem_ptr.offset(byte_offset) as *mut PhysRange,
                entries_per_color * color_count,
            )
        };

        (ranges, ranges_next_idx, exact_sizes)
    }

    /// Returns the address of the main mem region backing this structures as well as its size
    pub fn get_backing_mem(&self) -> (HostVirtAddr, usize) {
        (HostVirtAddr::new(self.raw_base_ptr as usize), self.bytes)
    }

    /// Fixed size of each color sub array. Does not mean that we have that
    /// many valid entries
    pub fn get_max_entries_per_color(&self) -> usize {
        self.entries_per_color
    }

    ///return (number of required bytes, number of entries per color)
    pub fn required_bytes<T: MemoryColoring>(
        all_regions: &[MemoryRegion],
        painter: &T,
    ) -> (usize, usize) {
        //compute required bytes to store color information
        let mut total_required = 0;
        // `exact_sizes`
        total_required += mem::size_of::<u64>() * T::COLOR_COUNT;
        // `ranges_next_idx`
        total_required += mem::size_of::<usize>() * T::COLOR_COUNT;

        //`ranges`
        let useable_mem: u64 = all_regions
            .iter()
            .map(|v| {
                if v.kind == MemoryRegionKind::UseableRAM {
                    v.end - v.start
                } else {
                    0
                }
            })
            .sum();
        //last term for some slack
        let expected_entries = useable_mem / painter.step_size();
        let expected_entries = expected_entries
            + (expected_entries % T::COLOR_COUNT as u64)
            + 100 * T::COLOR_COUNT as u64;
        total_required += expected_entries as usize * mem::size_of::<PhysRange>();

        let entries_per_color = expected_entries as usize / T::COLOR_COUNT;
        (total_required, entries_per_color)
    }

    pub fn new<T: MemoryColoring>(
        all_regions: &[MemoryRegion],
        painter: &T,
        raw_mem_ptr: *mut u8,
        raw_mem_bytes: usize,
    ) -> Result<Self, &'static str> {
        //Divice raw mem into slices
        let (required_bytes, entries_per_color) = Self::required_bytes(all_regions, painter);
        if raw_mem_bytes < required_bytes {
            return Err("Insufficient memory provided");
        }

        let (ranges, ranges_next_idx, exact_sizes) =
            Self::cust_mem_into_slices(raw_mem_ptr, T::COLOR_COUNT, entries_per_color);
        exact_sizes.fill(0);
        ranges_next_idx.fill(0);

        let mut s = Self {
            raw_base_ptr: raw_mem_ptr,
            bytes: raw_mem_bytes,
            ranges,
            exact_sizes,
            ranges_next_idx,
            entries_per_color,
        };
        s.paint_memory(all_regions, painter);
        Ok(s)
    }

    fn paint_memory<T: MemoryColoring>(&mut self, all_regions: &[MemoryRegion], painter: &T) {
        let step_size = painter.step_size() as usize;
        let mut cur: Option<(PhysRange, u64)> = None;
        for mr in all_regions.iter() {
            if mr.kind != MemoryRegionKind::UseableRAM {
                continue;
            }

            //inclusive
            let mr_start_aligned = HostPhysAddr::new(mr.start as usize)
                .align_up(step_size)
                .as_usize();
            //exclusive
            let mr_end_aligned = HostPhysAddr::new(mr.end as usize)
                .align_down(step_size)
                .as_usize();

            if mr_end_aligned <= mr_start_aligned {
                continue;
            }

            log::info!(
                "Start 0x{:08x}, End 0x{:08x}",
                mr.start as usize,
                mr.end as usize
            );
            log::info!(
                "Aligned Start 0x{:08x}, Aligned End 0x{:08x}",
                mr_start_aligned,
                mr_end_aligned
            );
            log::info!(
                "Size of aligned range: {} bytes -> {} MiB",
                mr_end_aligned - mr_start_aligned,
                (mr_end_aligned - mr_start_aligned) >> 20
            );
            for cur_addr in (mr_start_aligned..mr_end_aligned).step_by(step_size) {
                let new_color = painter.compute_color(HostPhysAddr::new(cur_addr));

                if let Some((mut cur_range, cur_color)) = cur {
                    //Have current range
                    //Case 1: color changed  or gap in paddr -> close current range
                    if new_color != cur_color || cur_range.end.as_usize() != cur_addr {
                        self.exact_sizes[cur_color as usize] += cur_range.size() as u64;
                        self.ranges[self.get_next_idx(cur_color)] = cur_range;
                        self.ranges_next_idx[cur_color as usize] += 1;

                        cur = Some((
                            PhysRange {
                                start: HostPhysAddr::new(cur_addr),
                                end: HostPhysAddr::new(cur_addr + step_size),
                            },
                            new_color,
                        ));
                    } else {
                        //Case 2: color stayed the same and phys contig -> extend current range
                        cur_range.end = cur_range.end + step_size;
                    }
                } else {
                    //First iteration, init current range
                    cur = Some((
                        PhysRange {
                            start: HostPhysAddr::new(cur_addr),
                            end: HostPhysAddr::new(cur_addr + step_size),
                        },
                        new_color,
                    ))
                }
            }
        }

        if let Some((range, color)) = cur {
            self.exact_sizes[color as usize] += range.size() as u64;
            self.ranges[self.get_next_idx(color)] = range;
            self.ranges_next_idx[color as usize] += 1;
        }
    }

    fn get_next_idx(&self, color: u64) -> usize {
        self.ranges_next_idx[color as usize] + (color as usize * self.entries_per_color)
    }

    pub fn get_color(&self, color: usize) -> &[PhysRange] {
        let start = color * self.entries_per_color;
        let end = start + self.ranges_next_idx[color];
        &self.ranges[start..end]
    }

    pub fn get_color_size(&self, color: usize) -> u64 {
        self.exact_sizes[color]
    }

    pub fn get_color_range_size(&self, first_color: u64, color_count: u64) -> usize {
        self.exact_sizes[first_color as usize..(first_color + color_count) as usize]
            .iter()
            .sum::<u64>() as usize
    }

    ///compute number of colors starting from `first_allowed` that are required to cover at least `required_bytes`
    /// Returns (incl. first color, color count, excact size in bytes)
    pub fn contig_color_range(
        &self,
        first_allowed: u64,
        required_bytes: usize,
    ) -> Result<(u64, u64, usize), ()> {
        let mut remaining_bytes: i64 = required_bytes as i64;
        let mut count = 0;
        for color_size in self.exact_sizes.iter().skip(first_allowed as usize) {
            remaining_bytes -= *color_size as i64;
            count += 1;
            if remaining_bytes <= 0 {
                break;
            }
        }
        if remaining_bytes > 0 {
            Err(())
        } else {
            Ok((
                first_allowed,
                count,
                required_bytes + remaining_bytes.abs() as usize,
            ))
        }
    }
}

#[cfg(feature = "coloring-allocator")]
#[cfg(test)]
mod test {
    extern crate alloc;
    use alloc::vec::Vec;

    use super::*;
    use crate::memory_painter::MyBitmap;

    #[derive(Debug, Clone, Default)]
    pub struct TestColoring {}

    impl TestColoring {
        //USER CONFIGURED VALUES

        //use 2 to the power of COLOR_ORDER many colors
        //keep in sync with TYCHE_COLOR_COUNT in linux/drivers/tyche/libraries/capabilities/include/color_bitmap.h
        pub const COLOR_ORDER: usize = 2;

        //shift out this many bits of the HPA; then interpret the lowest log2(COLOR_ORDER)
        //bits as the color
        pub const SHIFT: usize = 12;

        //DERIVED VALUES
        //mask to apply to page bits (after shifting) to get color id for address
        pub const COLOR_MASK: u64 = (1 << Self::COLOR_ORDER) - 1;
    }

    impl MemoryColoring for TestColoring {
        fn compute_color(&self, frame: HostPhysAddr) -> u64 {
            let color = (frame.as_u64() >> Self::SHIFT) & Self::COLOR_MASK;
            color
        }

        const COLOR_COUNT: usize = 1 << Self::COLOR_ORDER;
        const BYTES_FOR_COLOR_BITMAP: usize = Self::COLOR_COUNT / 8;

        type Bitmap = MyBitmap<{ Self::BYTES_FOR_COLOR_BITMAP }, { Self::COLOR_COUNT }>;

        fn new() -> Self {
            Self {}
        }

        fn step_size(&self) -> u64 {
            1 << Self::SHIFT
        }
    }

    #[test]
    fn simple_coloring() {
        let mut mem_regions = Vec::new();
        mem_regions.push(MemoryRegion {
            start: 0,
            end: 2 * TestColoring::COLOR_COUNT as u64 * (1 << 12),
            kind: crate::memory_painter::MemoryRegionKind::UseableRAM,
        });

        let (required_bytes, _) = ColorToPhysMap::required_bytes(&mem_regions, &TestColoring {});
        let mut buf: Vec<u8> = Vec::with_capacity(required_bytes);

        let ctp = ColorToPhysMap::new(
            &mem_regions,
            &TestColoring {},
            buf.as_mut_ptr(),
            required_bytes,
        )
        .expect("failed to create ctp");

        let cc = TestColoring::COLOR_COUNT;
        for color in 0..cc {
            let ranges = ctp.get_color(color);
            assert_eq!(ranges.len(), 2);
            assert_eq!(
                ranges[0],
                PhysRange::from((color * 4096, (color + 1) * 4096)),
                "Color {}",
                color
            );
            assert_eq!(
                ranges[1],
                PhysRange::from(((color + cc) * 4096, (color + cc + 1) * 4096)),
                "Color {}",
                color
            );
        }
    }

    #[test]
    fn size_tracking() {
        let mut mem_regions = Vec::new();
        mem_regions.push(MemoryRegion {
            start: 0,
            end: 1 * (1 << 20),
            kind: crate::memory_painter::MemoryRegionKind::UseableRAM,
        });
        mem_regions.push(MemoryRegion {
            start: 1 * (1 << 20),
            end: 2 * (1 << 20),
            kind: crate::memory_painter::MemoryRegionKind::Reserved,
        });
        mem_regions.push(MemoryRegion {
            start: 2 * (1 << 20),
            end: 3 * (1 << 20) + 4096,
            kind: crate::memory_painter::MemoryRegionKind::UseableRAM,
        });

        let (required_bytes, _) = ColorToPhysMap::required_bytes(&mem_regions, &TestColoring {});
        let mut buf: Vec<u8> = Vec::with_capacity(required_bytes);

        let ctp = ColorToPhysMap::new(
            &mem_regions,
            &TestColoring {},
            buf.as_mut_ptr(),
            required_bytes,
        )
        .expect("failed to create ctp");

        let mut total_size = 0;
        for idx in 0..TestColoring::COLOR_COUNT {
            total_size += ctp.get_color_size(idx);
        }
        assert_eq!(total_size, 2 * (1 << 20) + 4096);
    }
}
