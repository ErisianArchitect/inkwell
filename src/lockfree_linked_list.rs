use std::sync::atomic::{AtomicPtr, Ordering};


#[repr(C)]
#[derive(Debug)]
pub(crate) struct LockfreeLinkedListNode<T> {
    pub _value: T,
    pub next: AtomicPtr<Self>,
}

impl<T> LockfreeLinkedListNode<T> {
    #[must_use]
    #[inline]
    pub fn new(value: T) -> Box<Self> {
        Box::new(Self {
            _value: value,
            next: AtomicPtr::new(std::ptr::null_mut()),
        })
    }
}

#[derive(Debug)]
pub(crate) struct LockfreeLinkedList<T> {
    pub head: AtomicPtr<LockfreeLinkedListNode<T>>,
}

impl<T> LockfreeLinkedList<T> {
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            head: AtomicPtr::new(std::ptr::null_mut()),
        }
    }
    
    pub unsafe fn push_raw(
        &self,
        next: &AtomicPtr<LockfreeLinkedListNode<T>>,
        node: *const LockfreeLinkedListNode<T>,
    ) {
        let mut head = self.head.load(Ordering::Acquire);
        loop {
            next.store(head, Ordering::Relaxed);
            head = match self.head.compare_exchange_weak(head, node.cast_mut(), Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(new_head) => new_head,
            };
        }
    }
    
    #[must_use]
    pub fn push(&self, value: T) -> *mut T {
        // let mut old_head = self.head.load(Ordering::Acquire);
        let node = LockfreeLinkedListNode::new(value);
        unsafe { self.push_raw(&node.next, &*node); }
        // LockfreeLinkedListNode<T> is repr(C) with T as the first field.
        // That means that a pointer to LockfreeLinkedListNode<T> is also a pointer to T.
        // leak the node so that it can be cleaned up later.
        Box::into_raw(node).cast()
    }
}

impl<T> Drop for LockfreeLinkedList<T> {
    fn drop(&mut self) {
        let mut head = self.head.load(Ordering::Relaxed);
        loop {
            if head.is_null() {
                return;
            }
            let head_box = unsafe { Box::from_raw(head) };
            head = head_box.next.load(Ordering::Relaxed);
        }
    }
}