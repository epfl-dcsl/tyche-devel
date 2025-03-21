extern crate alloc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::{mem, slice};

use utils::{HostPhysAddr, HostVirtAddr};

use self::kmerge_iter::KmergeIter;
use crate::frame_allocator::PhysRange;
use crate::memory_painter::{
    ColorBitmap, MemoryColoring, MemoryRegion, MemoryRegionKind, PartitionBitmap,
};

mod kmerge_iter;

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

    /// Return exact size of colored memory within the given ranges
    pub fn get_colored_size(
        &self,
        start: HostPhysAddr,
        end: HostPhysAddr,
        colors: &PartitionBitmap,
    ) -> usize {
        let mut size = 0;
        for color in 0..colors.get_payload_bits_len() {
            if !colors.get(color) {
                continue;
            }
            let all_ranges = self.get_color(color);
            let sub_start_idx = all_ranges.partition_point(|v| v.end <= start);
            let sub = &all_ranges[sub_start_idx..];

            for pr in sub {
                if pr.start >= end {
                    break;
                }
                if start >= pr.start && start < pr.end {
                    // start fully contained, might not use full range
                    size += pr.end.as_usize() - start.as_usize();
                } else if end > pr.start && end < pr.end {
                    //end fully contained, might not use full range
                    size += end.as_usize() - pr.start.as_usize();
                } else {
                    size += pr.size();
                }
            }
        }
        return size;
    }

    /// Call `cb` on all memory with the specified colors in the given range.
    /// `cb` the results of `cb` are sorted and adjacent PhysRanges are already merged
    /// # Arguments
    /// - `cb` callback for visited ranges. Return `false` to stop the iteraton
    pub fn get_colored_ranges_ord<F>(
        &self,
        start: HostPhysAddr,
        end: HostPhysAddr,
        colors: &PartitionBitmap,
        mut cb: F,
    ) where
        F: FnMut(PhysRange) -> bool,
    {
        let mut slices = Vec::new();
        //for all colors find the sub ranges that overlap with our specified range
        for color in 0..colors.get_payload_bits_len() {
            if !colors.get(color) {
                continue;
            }
            let all_ranges = self.get_color(color);
            let sub_start_idx = all_ranges.partition_point(|v| v.end <= start);
            let sub = &all_ranges[sub_start_idx..];
            //n.b. that we operate on sub not all_ranges
            let local_end_idx = sub.partition_point(|v| v.start < end);
            let sub = &sub[..local_end_idx];
            slices.push(sub);
        }
        let merging_iter = KmergeIter::new(slices);
        let mut cur_opt: Option<PhysRange> = None;

        //iterate over phys ranges in ascending order
        for pr in merging_iter {
            //fixup pr in case that it is only a partial overlap
            let pr = if start >= pr.start && start < pr.end {
                // start fully contained, might not use full range
                PhysRange { start, end: pr.end }
            } else if end > pr.start && end < pr.end {
                //end fully contained, might not use full range
                PhysRange {
                    start: pr.start,
                    end,
                }
            } else {
                *pr
            };

            match &mut cur_opt {
                Some(cur_pr) => {
                    if cur_pr.end == pr.start {
                        cur_pr.end = pr.end;
                    } else {
                        if !cb(*cur_pr) {
                            return;
                        }
                        *cur_pr = pr;
                    }
                }
                None => cur_opt = Some(pr),
            }
        }
        if let Some(pr) = cur_opt {
            if !cb(pr) {
                return;
            }
        }
    }

    /// Compute the end HPA for such that start and end contain `colored_size` bytes considered only the specified colors
    pub fn get_color_offset_end(
        &self,
        start: HostPhysAddr,
        colored_size: usize,
        colors: &PartitionBitmap,
    ) -> Result<HostPhysAddr, ()> {
        let mut curr_end = start.as_usize();
        let mut curr_colored_size = 0;

        //iterate over colored mem with OPEN end until we gathered enough mem
        self.get_colored_ranges_ord(start, HostPhysAddr::new(usize::MAX), colors, |pr| {
            curr_colored_size += pr.size();
            if curr_colored_size <= colored_size {
                curr_end = pr.end.as_usize();
                if curr_colored_size == colored_size {
                    false
                } else {
                    true
                }
            } else {
                //using pr we overshot the desired size ->  cut in the middle and end iteration
                let overshot = curr_colored_size - colored_size;
                curr_end = pr.end.as_usize() - overshot;
                return false;
            }
        });

        if curr_colored_size >= colored_size {
            Ok(HostPhysAddr::new(curr_end))
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod test {
    extern crate alloc;
    use alloc::fmt::Write;
    use alloc::string::String;
    use alloc::vec::Vec;

    use pretty_assertions::assert_eq;

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

    #[test]
    fn colored_size() {
        let mut mem_regions = Vec::new();
        mem_regions.push(MemoryRegion {
            start: 0,
            end: 12 * (1 << 12),
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

        let mut allowed_colors = PartitionBitmap::new();
        allowed_colors.set(0, true);

        //coloring has 4 colours -> 3 pages per color
        let got_size = ctp.get_colored_size(
            HostPhysAddr::new(0),
            HostPhysAddr::new(12 * (1 << 12)),
            &allowed_colors,
        );
        assert_eq!(got_size, 3 * (1 << 12), "Unexpected size 0x{:x}", got_size);

        allowed_colors.set(3, true);
        let got_size = ctp.get_colored_size(
            HostPhysAddr::new(0),
            HostPhysAddr::new(12 * (1 << 12)),
            &allowed_colors,
        );
        assert_eq!(got_size, 6 * (1 << 12), "Unexpected size 0x{:x}", got_size);

        //first range for first color is excluded by start paddr
        let got_size = ctp.get_colored_size(
            HostPhysAddr::new(1 * (1 << 12)),
            HostPhysAddr::new(12 * (1 << 12)),
            &allowed_colors,
        );
        assert_eq!(got_size, 5 * (1 << 12), "Unexpected size 0x{:x}", got_size);

        //last range for last color is excluded by end paddr
        let got_size = ctp.get_colored_size(
            HostPhysAddr::new(0 * (1 << 12)),
            HostPhysAddr::new(11 * (1 << 12)),
            &allowed_colors,
        );
        assert_eq!(got_size, 5 * (1 << 12), "Unexpected size 0x{:x}", got_size);
    }

    #[test]
    fn colored_ranges_ord() {
        let mut mem_regions = Vec::new();
        mem_regions.push(MemoryRegion {
            start: 0,
            end: 12 * (1 << 12),
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

        let mut allowed_colors = PartitionBitmap::new();
        allowed_colors.set(0, true);

        let mut got_ranges = Vec::new();
        ctp.get_colored_ranges_ord(
            HostPhysAddr::new(0),
            HostPhysAddr::new(12 * (1 << 12)),
            &allowed_colors,
            |pr| {
                got_ranges.push(pr);
                true
            },
        );

        let want = [
            PhysRange::from((0 * (1 << 12), 1 * (1 << 12))),
            PhysRange::from((4 * (1 << 12), 5 * (1 << 12))),
            PhysRange::from((8 * (1 << 12), 9 * (1 << 12))),
        ];

        assert_eq!(got_ranges, want, "color 0 only failed");

        //colors 0 and 1 allowed adjacent ranges should get merged
        allowed_colors.set(1, true);
        got_ranges.clear();
        ctp.get_colored_ranges_ord(
            HostPhysAddr::new(0),
            HostPhysAddr::new(12 * (1 << 12)),
            &allowed_colors,
            |pr| {
                got_ranges.push(pr);
                true
            },
        );
        let want = [
            PhysRange::from((0 * (1 << 12), 2 * (1 << 12))),
            PhysRange::from((4 * (1 << 12), 6 * (1 << 12))),
            PhysRange::from((8 * (1 << 12), 10 * (1 << 12))),
        ];
        let mut got_str = String::new();
        let mut want_str = String::new();
        write!(got_str, "{:x?}", got_ranges).unwrap();
        write!(want_str, "{:x?}", want).unwrap();
        assert_eq!(got_str, want_str, "color 0 and 1  failed");

        //add color color 3
        allowed_colors.set(3, true);
        got_ranges.clear();
        ctp.get_colored_ranges_ord(
            HostPhysAddr::new(0),
            HostPhysAddr::new(12 * (1 << 12)),
            &allowed_colors,
            |pr| {
                got_ranges.push(pr);
                true
            },
        );
        let want = [
            PhysRange::from((0 * (1 << 12), 2 * (1 << 12))), //0+1
            PhysRange::from((3 * (1 << 12), 6 * (1 << 12))), //3+0+1
            PhysRange::from((7 * (1 << 12), 10 * (1 << 12))), //3+0+1
            PhysRange::from((11 * (1 << 12), 12 * (1 << 12))), //3
        ];
        let mut got_str = String::new();
        let mut want_str = String::new();
        write!(got_str, "{:x?}", got_ranges).unwrap();
        write!(want_str, "{:x?}", want).unwrap();
        assert_eq!(got_str, want_str, "color 0, 1 and 3 failed");
    }

    #[test]
    fn get_colored_offset_end() {
        let mut mem_regions = Vec::new();
        mem_regions.push(MemoryRegion {
            start: 0,
            end: 12 * (1 << 12),
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

        let mut allowed_colors = PartitionBitmap::new();
        allowed_colors.set(0, true);
        allowed_colors.set(2, true);

        let got = ctp
            .get_color_offset_end(HostPhysAddr::new(0), 2 * (1 << 12), &allowed_colors)
            .expect("get_color_offset_end failed");

        let mut got_str = String::new();
        let mut want_str = String::new();
        write!(got_str, "{:x?}", got.as_u64()).unwrap();
        write!(want_str, "{:x?}", 3 * (1 << 12)).unwrap();
        assert_eq!(got_str, want_str);

        //want error because not enough mem
        let got = ctp.get_color_offset_end(HostPhysAddr::new(0), 7 * (1 << 12), &allowed_colors);
        assert_eq!(got, Err(()));
    }
}
