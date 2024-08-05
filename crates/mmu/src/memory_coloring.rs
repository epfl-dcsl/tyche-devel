use core::fmt::Display;
use core::ops::BitOrAssign;

use utils::HostPhysAddr;

use crate::frame_allocator::PhysRange;
pub mod color_to_phys;

///Memory colorings as described by the Magheira paper
pub trait MemoryColoring {
    /// Amount of different colors
    const COLOR_COUNT: usize;
    ///Number of bytes required for the color bitmap to represent the COLOR_COUNT many colors
    const BYTES_FOR_COLOR_BITMAP: usize;

    type Bitmap: ColorBitmap + Clone;

    /// Computes the memory color for the given address
    fn compute_color(&self, frame: HostPhysAddr) -> u64;
}

//for akward tpye conversion in test code for capa engine
//if you set the active memory coloring outside this limit, some tests and assertions fail
pub const MAX_COLOR_BITMAP_BYTES: usize = 256;
pub const MAX_COLOR_COUNT: usize = MAX_COLOR_BITMAP_BYTES * 8;

/// Memory Coloring that assings same color to all memory
/// Intended for places where we do not want to further subdivice
/// the memory but still have to specify a memory coloring
#[derive(Clone, Copy)]
pub struct AllSameColor {}

impl MemoryColoring for AllSameColor {
    const COLOR_COUNT: usize = 1;

    const BYTES_FOR_COLOR_BITMAP: usize = 1;

    type Bitmap = MyBitmap<{ Self::BYTES_FOR_COLOR_BITMAP }, { Self::COLOR_COUNT }>;

    fn compute_color(&self, _frame: HostPhysAddr) -> u64 {
        0
    }
}

impl AllSameColor {
    pub fn allow_all_bitmap() -> <AllSameColor as MemoryColoring>::Bitmap {
        MyBitmap::new_with_value(true)
    }
}

pub type ActiveMemoryColoring = DummyMemoryColoring;

pub trait ColorBitmap {
    /// Creates a new bitmap with all bits set to false
    fn new_nonconst() -> Self;
    /// Set the bit at `bit_idx` to `value`
    fn set(&mut self, bit_idx: usize, value: bool);
    /// Return the value of bit at `bit_idx`
    fn get(&self, bit_idx: usize) -> bool;
    ///Returns ("number of bytes for the internal bitmap", "number of things bitmap can track")
    fn dimensions(&self) -> (usize, usize);
    //get raw underlying array
    fn get_raw(&self) -> &[u8];
}

//TODO: add unit tests
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Bitmap to represent `K`  different things. `N`` represents the number
/// of bytes required for the bit map (i.e. align_up(K,8)). The is an extra
/// param, so that we can keep everything const as const prevserving computations are not yet
/// stable
// Implementation note: we index the individual bytes from right to left to work more
// naturally with shift operations. Example bit idx 8 would be in the second byte and selected by
// mask 0b0000_0001 NOT 0b1000_0000
pub struct MyBitmap<const N: usize, const K: usize> {
    //number of "payload" bits in `data`. The remaining bits are overhang/unused
    bits_count: usize,
    data: [u8; N],
}

impl<const N: usize, const K: usize> ColorBitmap for MyBitmap<N, K> {
    /// Creates a new bitmap with all bits set to false
    fn new_nonconst() -> Self {
        Self {
            data: [0_u8; N],
            bits_count: K,
        }
    }
    /// Set the bit at `bit_idx` to `value`
    fn set(&mut self, bit_idx: usize, value: bool) {
        assert!(
            bit_idx < self.bits_count,
            "Out of bounds bit idx: bit_idx={}, bits_count={}",
            bit_idx,
            self.bits_count
        );
        //idx of the byte in `data` that stores the targeted bit
        let byte_idx = bit_idx / 8;
        //offset inside the targeted byte that stores the bit
        let byte_offset = bit_idx % 8;

        match value {
            false => {
                let mask = !(0x1_u8 << byte_offset);
                self.data[byte_idx] &= mask;
            }
            true => {
                let mask = 0x1_u8 << byte_offset;
                self.data[byte_idx] |= mask;
            }
        };
    }

    /// Return the value of bit at `bit_idx`
    fn get(&self, bit_idx: usize) -> bool {
        assert!(
            bit_idx < self.bits_count,
            "Out of bounds bit idx: bit_idx={}, bits_count={}",
            bit_idx,
            self.bits_count
        );
        //idx of the byte in `data` that stores the targeted bit
        let byte_idx = bit_idx / 8;
        //offset inside the targeted byte that stores the bit
        let byte_offset = bit_idx % 8;

        let selection_mask = (0x1_u8) << byte_offset;
        (self.data[byte_idx] & selection_mask) != 0
    }

    fn dimensions(&self) -> (usize, usize) {
        (N, K)
    }

    fn get_raw(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize, const K: usize> MyBitmap<N, K> {
    /// Creates a new bitmap with all bits set to false
    pub const fn new() -> Self {
        Self {
            data: [0_u8; N],
            bits_count: K,
        }
    }

    pub fn new_from(data: [u8; N]) -> Self {
        Self {
            data,
            bits_count: K,
        }
    }

    /// Length of "virtual" array that covers only the payload bits
    /// Use this if you wan to iterate over all bits via `set` or `get`
    pub fn get_payload_bits_len(&self) -> usize {
        self.bits_count
    }

    pub fn new_with_value(value: bool) -> Self {
        let init_value = match value {
            true => 0xff,
            false => 0x0,
        };
        Self {
            data: [init_value; N],
            bits_count: K,
        }
    }

    /// Set all bits to `value`
    pub fn set_all(&mut self, value: bool) {
        let value = match value {
            true => 0xff_u8,
            false => 0x0_u8,
        };
        for v in self.data.iter_mut() {
            *v = value;
        }
    }

    /// Return true if all bits are set to zero
    pub fn all_bits_unset(&self) -> bool {
        for v in self.data {
            if v != 0 {
                return false;
            }
        }
        return true;
    }

    /// Return true if the set bits in `self` are a subset of the bits set in `&other`
    pub fn is_subset_of(&self, other: &MyBitmap<N, K>) -> bool {
        //as data is of byte granularity there might be a few trailing bytes at the end
        //this is the index of the last byte in data where all bits are used
        let idx_last_full_byte = if self.bits_count % 8 == 0 {
            self.data.len() - 1
        } else {
            self.data.len() - 2
        };

        //check "full bytes"
        for idx in 0..idx_last_full_byte + 1 {
            if (self.data[idx] | other.data[idx]) != other.data[idx] {
                return false;
            }
        }

        //if last byte has some trailing bits, discard them before comparing
        if idx_last_full_byte != self.data.len() - 1 {
            let payload_bit_count = self.bits_count % 8;
            assert!(payload_bit_count >= 1);
            //left shift will set low bits to zero, invert will set allt
            let mask = !(0xff_u8 << payload_bit_count);
            let self_payload = self.data[idx_last_full_byte + 1] & mask;
            let other_payload = other.data[idx_last_full_byte + 1] & mask;
            if (self_payload | other_payload) != other_payload {
                return false;
            }
        }

        return true;
    }
}

impl<const N: usize, const K: usize> BitOrAssign for MyBitmap<N, K> {
    fn bitor_assign(&mut self, rhs: Self) {
        for idx in 0..N {
            self.data[idx] |= rhs.data[idx]
        }
    }
}

impl<const N: usize, const K: usize> Display for MyBitmap<N, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MyBitmap(allowed color id(s): ")?;
        for color_id in 0..self.get_payload_bits_len() {
            if self.get(color_id) {
                write!(f, "{} ", color_id)?;
            }
        }
        write!(f, ")")
    }
}

pub type PartitionBitmap = MyBitmap<
    { ActiveMemoryColoring::BYTES_FOR_COLOR_BITMAP },
    { ActiveMemoryColoring::COLOR_COUNT },
>;

/// This memory coloring is only intended as an example and does not give
/// You any isolation guarantees
#[derive(Debug, Clone)]
pub struct DummyMemoryColoring {}

impl DummyMemoryColoring {
    //use 2 to the power of COLOR_ORDER many colors
    pub const COLOR_ORDER: usize = 5;
    //mask to apply to page bits (after shifting) to get color id for address
    pub const COLOR_MASK: u64 = (1 << Self::COLOR_ORDER) - 1;

    const SHIFT: usize = 20;
}

impl MemoryColoring for DummyMemoryColoring {
    fn compute_color(&self, frame: HostPhysAddr) -> u64 {
        let color = (frame.as_u64() >> Self::SHIFT) & Self::COLOR_MASK;
        color
    }

    const COLOR_COUNT: usize = 1 << Self::COLOR_ORDER;
    const BYTES_FOR_COLOR_BITMAP: usize = Self::COLOR_COUNT / 8;

    type Bitmap = MyBitmap<{ Self::BYTES_FOR_COLOR_BITMAP }, { Self::COLOR_COUNT }>;
}

//TODO: add feature flags to switch this
/// Alias type for the  the currently active memory coloring
pub type MemoryColoringType = DummyMemoryColoring;

#[derive(Debug, Clone, Copy)]
#[repr(C)]

/// Represents a contiguous range of memory colors
pub struct ColorRange {
    /// First color in this range
    pub first_color: u64,
    /// Number of colors in in this
    /// i.e. `first_color+color_count-1` is the last used color
    pub color_count: u64,
    /// Number of bytes that this color range provides
    pub mem_bytes: usize,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RamRegionsInRange {
    pub range: PhysRange,
    pub mem_bytes: usize,
}

/// Wrapper type to dynmaically handle
/// contiguous pyhs ranges and scattered colored ranges
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum MemoryRange {
    /// Represents all pages within and upper and lower address limits that have the specified colors
    ColoredRange(ColorRange),
    /// Physical Contiguous Memory Range
    SinglePhysContigRange(PhysRange),
    /// Represents all useable ram regions in that range under the current memory map. Might not be contiguous if there
    /// are gaps in the memory map
    AllRamRegionInRange(RamRegionsInRange),
}

#[cfg(test)]
pub mod test {
    use super::MyBitmap;
    use crate::memory_coloring::ColorBitmap;

    #[test]
    fn test_payload_bits_len() {
        const N: usize = 2;
        const K: usize = 9;
        let mbm = MyBitmap::<N, K>::new();
        assert_eq!(mbm.get_payload_bits_len(), K);
    }

    #[test]
    fn test_get_set() {
        const N: usize = 2;
        const K: usize = 12;
        let mut mbm = MyBitmap::<N, K>::new();

        //initially all bits should be zero
        for idx in 0..mbm.get_payload_bits_len() {
            assert_eq!(mbm.get(idx), false);
        }

        //set some values
        let idx_should_be_high = |idx| match idx {
            0 | 3 | 7 | 11 => true,
            _ => false,
        };
        for idx in 0..mbm.get_payload_bits_len() {
            if idx_should_be_high(idx) {
                mbm.set(idx, true);
            }
        }

        //check that only the requested values have been set
        for idx in 0..mbm.get_payload_bits_len() {
            if idx_should_be_high(idx) {
                assert_eq!(mbm.get(idx), true, "Idx {}, Expected high, got low", idx);
            } else {
                assert_eq!(mbm.get(idx), false, "Idx {}, Expected low, got high", idx);
            }
        }
    }

    #[test]
    fn test_is_subset_of_1() {
        const N: usize = 2;
        const K: usize = 9;
        let mut superset = MyBitmap::<N, K>::new();
        let mut subset = MyBitmap::<N, K>::new();

        let superset_high_indices: &[usize] = &[0, 6, 8];
        let subset_high_indices: &[usize] = &[0, 8];

        for idx in superset_high_indices {
            superset.set(*idx, true);
        }

        for idx in subset_high_indices {
            subset.set(*idx, true);
        }

        assert!(subset.is_subset_of(&superset), "Expected to be subset");
        assert!(
            !superset.is_subset_of(&subset),
            "Expected NOT to bet subset"
        );
    }
}
