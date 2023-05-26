//! Utils

use core::iter::Iterator;

/// An iterator for a bitmap indexes.
pub struct BitmapIterator {
    bitmap: u64,
}

impl BitmapIterator {
    pub fn new(bitmap: u64) -> Self {
        Self { bitmap }
    }
}

impl Iterator for BitmapIterator {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.bitmap.trailing_zeros();

        if idx == 64 {
            // There is only zeroes in the bitmap
            return None;
        }

        // Reset the bit
        self.bitmap = self.bitmap ^ (1 << idx);
        Some(idx as usize)
    }
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap_iterator() {
        let mut bitmap = BitmapIterator::new(0b1010);
        assert_eq!(bitmap.next(), Some(1));
        assert_eq!(bitmap.next(), Some(3));
        assert_eq!(bitmap.next(), None);
    }
}
