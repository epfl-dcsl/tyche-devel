//! Generational Arena

use core::marker::PhantomData;
use core::ops::{Index, IndexMut};

use super::free_list::{FreeList, FreeListIterator};

// ——————————————————————————— Generational Arena ——————————————————————————— //

/// A generational arena.
pub(crate) struct GenArena<T, const N: usize> {
    /// The baking store from which objects are allocated.
    store: [T; N],

    /// The free list, where free_list[n] returns the index of the next free object.
    free_list: FreeList<N>,

    /// The generation, used to protect from use after free.
    gen: [u64; N],
}

impl<T, const N: usize> GenArena<T, N> {
    pub const fn new(store: [T; N]) -> Self {
        Self {
            store,
            free_list: FreeList::new(),
            gen: [0; N],
        }
    }

    pub fn allocate(&mut self, item: T) -> Option<Handle<T>> {
        self.free_list.allocate().map(|idx| {
            let gen = self.gen[idx];
            let handle = Handle {
                idx,
                gen,
                _type: PhantomData,
            };

            self[handle] = item;
            handle
        })
    }

    /// Free the handle and allocated memory. This invalidate all existing handles to that object.
    pub fn free(&mut self, handle: Handle<T>) {
        self.free_list.free(handle.idx);
        self.gen[handle.idx] += 1;
    }

    #[allow(dead_code)]
    pub fn get_mut(&mut self, handle: Handle<T>) -> Option<&mut T> {
        let idx = handle.idx;
        if self.gen[idx] == handle.gen {
            Some(&mut self.store[idx])
        } else {
            None
        }
    }

    pub fn get(&self, handle: Handle<T>) -> Option<&T> {
        let idx = handle.idx;
        if self.gen[idx] == handle.gen {
            Some(&self.store[idx])
        } else {
            None
        }
    }
}

// ———————————————————————————————— Indexing ———————————————————————————————— //

impl<T, const N: usize> Index<Handle<T>> for GenArena<T, N> {
    type Output = T;

    #[inline]
    fn index(&self, handle: Handle<T>) -> &Self::Output {
        let idx = handle.idx;
        if self.gen[idx] != handle.gen {
            panic!("Invalid generation, this is likely a use after free");
        }
        &self.store[idx]
    }
}

impl<T, const N: usize> IndexMut<Handle<T>> for GenArena<T, N> {
    fn index_mut(&mut self, handle: Handle<T>) -> &mut Self::Output {
        let idx = handle.idx;
        if self.gen[idx] != handle.gen {
            panic!("Invalid generation, this is likely a use after free");
        }
        &mut self.store[idx]
    }
}

// ————————————————————————————————— Handle ————————————————————————————————— //

/// An handle to an object of type T allocated in a Typed Arena.
pub struct Handle<T> {
    idx: usize,
    gen: u64,
    _type: PhantomData<T>,
}

impl<T> Handle<T> {
    /// Returns a fresh handle that will cause a panic if used.
    pub const fn new_invalid() -> Self {
        Self {
            idx: usize::MAX,
            gen: u64::MAX,
            _type: PhantomData,
        }
    }

    pub fn is_invalid(self) -> bool {
        self.gen == u64::MAX && self.idx == usize::MAX
    }

    pub fn idx(self) -> usize {
        self.idx
    }
}

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        Self {
            idx: self.idx,
            gen: self.gen,
            _type: PhantomData,
        }
    }
}

impl<T> Copy for Handle<T> {}

impl<T> PartialEq for Handle<T> {
    fn eq(&self, other: &Self) -> bool {
        self.idx == other.idx && self.gen == other.gen && self._type == other._type
    }
}

impl<T> Eq for Handle<T> {}

// ———————————————————————————————— Iterator ———————————————————————————————— //

pub(crate) struct ArenaIterator<'a, T, const N: usize> {
    arena: &'a GenArena<T, N>,
    iterator: FreeListIterator<'a, N>,
}

impl<'a, T, const N: usize> Iterator for ArenaIterator<'a, T, N> {
    type Item = Handle<T>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.iterator.next()?;
        Some(Handle {
            idx: next,
            gen: self.arena.gen[next],
            _type: PhantomData,
        })
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a GenArena<T, N> {
    type Item = Handle<T>;
    type IntoIter = ArenaIterator<'a, T, N>;

    fn into_iter(self) -> Self::IntoIter {
        ArenaIterator {
            arena: self,
            iterator: self.free_list.into_iter(),
        }
    }
}

// ———————————————————————————————— Display ————————————————————————————————— //

impl<T> core::fmt::Debug for Handle<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "H({}, gen {})", self.idx, self.gen)
    }
}

impl<T> core::fmt::Display for Handle<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "H({}, gen {})", self.idx, self.gen)
    }
}
