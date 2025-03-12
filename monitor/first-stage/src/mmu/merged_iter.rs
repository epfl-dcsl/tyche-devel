extern crate alloc;

use alloc::vec::Vec;
use alloc::collections::BinaryHeap;
use core::cmp::Reverse;

/// Merges multiple sorted vectors into a single sorted iterator that merges the elements from the vectors
pub struct AllocHeapMergedIter<T>
where
    T: Ord,
{
    heap: BinaryHeap<Reverse<(T, usize)>>,
    iterators: Vec<alloc::vec::IntoIter<T>>,
}

impl<T> AllocHeapMergedIter<T>
where
    T: Ord,
{
    pub fn new(mut vectors: Vec<Vec<T>>) -> Self {
        let mut heap = BinaryHeap::new();
        let mut iterators: Vec<_> = vectors.drain(..).map(|v| v.into_iter()).collect();

        // Initialize the heap with the first element of each iterator
        for (i, it) in iterators.iter_mut().enumerate() {
            if let Some(value) = it.next() {
                heap.push(Reverse((value, i)));
            }
        }

        AllocHeapMergedIter { heap, iterators }
    }
}

impl<T> Iterator for AllocHeapMergedIter<T>
where
    T: Ord,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(Reverse((val, i))) = self.heap.pop() {
            // Push the next element from the same iterator
            if let Some(next_val) = self.iterators[i].next() {
                self.heap.push(Reverse((next_val, i)));
            }
            Some(val)
        } else {
            None
        }
    }
}