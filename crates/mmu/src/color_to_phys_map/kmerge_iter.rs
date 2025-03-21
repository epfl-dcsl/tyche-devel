extern crate alloc;

use alloc::collections::BinaryHeap;
use alloc::vec::Vec;
use core::cmp::Reverse;
use core::slice;

/// Merges multiple sorted vectors into a single sorted iterator that merges the elements from the vectors
pub struct KmergeIter<'a, T>
where
    T: Ord,
{
    heap: BinaryHeap<Reverse<(&'a T, usize)>>,
    iterators: Vec<slice::Iter<'a, T>>,
}

impl<'a, T> KmergeIter<'a, T>
where
    T: Ord,
{
    pub fn new(vectors: Vec<&'a [T]>) -> Self {
        let mut heap = BinaryHeap::new();
        // let mut iterators: Vec<IntoIter<T>> = vectors.drain(..).map(|v| v.into_iter()).collect();
        let mut iterators: Vec<_> = vectors.iter().map(|v| v.iter()).collect();

        // Initialize the heap with the first element of each iterator
        for (i, it) in iterators.iter_mut().enumerate() {
            if let Some(value) = it.next() {
                heap.push(Reverse((value, i)));
            }
        }

        KmergeIter { heap, iterators }
    }
}

impl<'a, T> Iterator for KmergeIter<'a, T>
where
    T: Ord,
{
    type Item = &'a T;

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
