//! Generational Arena backed by `talc`

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::Ordering;
use core::marker::PhantomData;
use core::ops::{Index, IndexMut};

use talc::{ErrOnOom, Talc, Talck};

use crate::CapaError;

#[global_allocator]
pub static GLOBAL_ALLOCATOR: Talck<spin::Mutex<()>, ErrOnOom> = Talc::new(ErrOnOom).lock();

/*
struct AllocdAdapter {
    virt_offset: Mutex<Cell<usize>>,
    inner: &'static Talck<spin::Mutex<()>, ErrOnOom>,
    allocated_mem: Mutex<RefCell<u64>>,
}

static CAPA_ALLOC_ADAPTER: AllocdAdapter = AllocdAdapter {
    virt_offset: Mutex::new(Cell::new(0)),
    inner: &GLOBAL_ALLOCATOR,
    allocated_mem: Mutex::new(RefCell::new(0)),
};
*/
pub struct GenArena<T, const N: usize> {
    limit: usize,
    entries: Vec<Option<T>>,
    generations: Vec<u64>,
    free_list: Vec<usize>, // stack of free indices
}

impl<T, const N: usize> GenArena<T, N> {
    pub fn new() -> Self {
        Self {
            limit: N,
            entries: Vec::new(),
            generations: Vec::new(),
            free_list: Vec::new(),
        }
    }

    pub fn allocate(&mut self, value: T) -> Option<Handle<T>> {
        if let Some(idx) = self.free_list.pop() {
            self.entries[idx] = Some(value);
            self.generations[idx] += 1;
            Some(Handle {
                idx,
                gen: self.generations[idx],
                _type: PhantomData,
            })
        } else {
            let idx = self.entries.len();
            self.entries.push(Some(value));
            self.generations.push(0);
            Some(Handle {
                idx,
                gen: 0,
                _type: PhantomData,
            })
        }
    }

    pub fn free(&mut self, handle: Handle<T>) -> Option<T> {
        if handle.idx >= self.entries.len() {
            return None;
        }

        if self.generations[handle.idx] != handle.gen {
            return None;
        }

        let slot = self.entries[handle.idx].take();
        if slot.is_some() {
            self.free_list.push(handle.idx);
        }
        slot
    }

    pub fn get(&self, handle: Handle<T>) -> Option<&T> {
        self.entries
            .get(handle.idx)
            .and_then(|entry| entry.as_ref())
            .filter(|_| self.generations[handle.idx] == handle.gen)
    }

    pub fn get_mut(&mut self, handle: Handle<T>) -> Option<&mut T> {
        self.entries
            .get_mut(handle.idx)
            .and_then(|entry| entry.as_mut())
            .filter(|_| self.generations[handle.idx] == handle.gen)
    }

    pub fn has_capacity_for(&self, _count: usize) -> Result<(), CapaError> {
        //TODO
        Ok(())
    }

    pub fn capacity(&self) -> usize {
        self.limit
    }
}

// ———————————————————————————————— Indexing ———————————————————————————————— //

impl<T, const N: usize> Index<Handle<T>> for GenArena<T, N> {
    type Output = T;

    #[inline]
    fn index(&self, handle: Handle<T>) -> &Self::Output {
        let idx = handle.idx;
        if self.generations[idx] != handle.gen {
            panic!("Invalid generation, this is likely a use after free");
        }
        self.entries[idx].as_ref().unwrap()
    }
}

impl<T, const N: usize> IndexMut<Handle<T>> for GenArena<T, N> {
    fn index_mut(&mut self, handle: Handle<T>) -> &mut Self::Output {
        let idx = handle.idx;
        if self.generations[idx] != handle.gen {
            panic!("Invalid generation, this is likely a use after free");
        }
        self.entries[idx].as_mut().unwrap()
    }
}

// ————————————————————————————————— Handle ————————————————————————————————— //

/// An handle to an object of type T allocated in a Typed Arena.
pub struct Handle<T> {
    idx: usize,
    gen: u64,
    _type: PhantomData<T>,
}

impl<T> PartialOrd for Handle<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Handle<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.idx.cmp(&other.idx) {
            Ordering::Equal => self.gen.cmp(&other.gen),
            other => other,
        }
    }
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

// ———————————————————————————————— Iterator ———————————————————————————————— //

pub struct ArenaIterator<'a, T, const N: usize> {
    arena: &'a GenArena<T, N>,
    next_idx: usize,
}

impl<T, const N: usize> GenArena<T, N> {
    pub fn iter(&self) -> ArenaIterator<'_, T, N> {
        ArenaIterator {
            arena: self,
            next_idx: 0,
        }
    }
}

impl<'a, T, const N: usize> Iterator for ArenaIterator<'a, T, N> {
    type Item = Handle<T>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next_idx < self.arena.entries.len() {
            let idx = self.next_idx;
            self.next_idx += 1;

            if let Some(ref _value) = self.arena.entries[idx] {
                // Valid allocated entry
                let gen = self.arena.generations[idx];
                return Some(Handle {
                    idx,
                    gen,
                    _type: PhantomData,
                });
            }
            // else, continue to next index
        }
        None
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a GenArena<T, N> {
    type Item = Handle<T>;
    type IntoIter = ArenaIterator<'a, T, N>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
