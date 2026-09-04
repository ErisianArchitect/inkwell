
use ::core::{
    ptr::{
        NonNull,
    },
};

use ::llvm_sys::{
    orc2::{
        LLVMOrcResourceTrackerRef,
        LLVMOrcOpaqueResourceTracker,
    },
};

// TODO (ErisianArchitect): ResourceTracker documentation.
#[repr(transparent)]
#[derive(Debug)]
pub struct ResourceTracker {
    ptr: NonNull<LLVMOrcOpaqueResourceTracker>,
}

impl ResourceTracker {
    /// Create a [ResourceTracker] instance from a raw [LLVMOrcResourceTrackerRef] without checking if it is null.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer is either null, or does not point to a valid
    /// [LLVMOrcResourceTrackerRef].
    #[must_use]
    #[inline(always)]
    pub unsafe fn from_raw_unchekced(ptr: LLVMOrcResourceTrackerRef) -> Self {
        Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        }
    }

    /// Create a [ResourceTracker] instance from a raw [LLVMOrcResourceTrackerRef]. This function will only ensure that the
    /// pointer is non-null, it cannot verify that the reference is valid.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer does not point to a valid [LLVMOrcResourceTrackerRef].
    #[must_use]
    #[inline]
    pub unsafe fn from_raw(ptr: LLVMOrcResourceTrackerRef) -> Option<Self> {
        Some(Self {
            ptr: NonNull::new(ptr)?,
        })
    }

    /// Returns the inner [LLVMOrcResourceTrackerRef].
    ///
    /// # NOTE
    /// [ResourceTracker] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcResourceTrackerRef {
        self.ptr.as_ptr()
    }
}
