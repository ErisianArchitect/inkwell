use std::sync::atomic::{AtomicPtr, Ordering};


#[repr(C)]
#[derive(Debug)]
pub(crate) struct LockfreeLinkedListNode<T> {
    _value: T,
    next: AtomicPtr<Self>,
}

impl<T> LockfreeLinkedListNode<T> {
    #[must_use]
    #[inline]
    fn new(value: T) -> Box<Self> {
        Box::new(Self {
            _value: value,
            next: AtomicPtr::new(std::ptr::null_mut()),
        })
    }
}

#[derive(Debug)]
pub(crate) struct LockfreeLinkedList<T> {
    head: AtomicPtr<LockfreeLinkedListNode<T>>,
}

impl<T> LockfreeLinkedList<T> {
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            head: AtomicPtr::new(std::ptr::null_mut()),
        }
    }
    
    #[must_use]
    pub fn push(&self, value: T) -> *mut T {
        let mut old_head = self.head.load(Ordering::Acquire);
        let mut node = LockfreeLinkedListNode::new(value);
        let node_ptr = node.as_mut() as *mut LockfreeLinkedListNode<T>;
        loop {
            node.next.store(old_head, Ordering::Relaxed);
            match self.head.compare_exchange_weak(old_head, node_ptr, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(head) => old_head = head,
            }
        }
        // leak the node so that it can be cleaned up later.
        Box::leak(node);
        // LockfreeLinkedListNode<T> is repr(C) with T as the first field.
        // That means that a pointer to LockfreeLinkedListNode<T> is also a pointer to T.
        node_ptr.cast()
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