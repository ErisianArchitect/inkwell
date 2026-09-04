
use ::core::{
    ptr::{
        NonNull,
    },
    mem::{
        ManuallyDrop,
    },
};

use ::llvm_sys::{
    orc2::{
        LLVMOrcResourceTrackerRef,
        LLVMOrcOpaqueResourceTracker,
        LLVMOrcResourceTrackerRemove,
        LLVMOrcReleaseResourceTracker,
        LLVMOrcResourceTrackerTransferTo,
    },
};

use crate::{
    error::{
        LLVMError,
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

    /// Remove all resources associated with this [ResourceTracker].
    pub fn remove(&self) -> Result<(), LLVMError> {
        // removeResourceTracker locks the ExecutionSession, which makes this function thread-safe.
        // C++ source code:
        // [https://github.com/llvm/llvm-project/blob/2078da43e25a4623cab2d0d60decddf709aaea28/llvm/lib/ExecutionEngine/Orc/Core.cpp#L2181]
        // Documentation:
        // [https://llvm.org/doxygen/group__LLVMCExecutionEngineORC.html#gaeb2dc0257d714c0c7ba3d8ceb796cd35]
        LLVMError::result_from_error_ref(unsafe { LLVMOrcResourceTrackerRemove(self.as_ptr()) })
    }

    /// Transfers tracking of all resources associated with the `source` [ResourceTracker] into this [ResourceTracker].
    pub fn transfer_from(&self, source: Self) {
        // The execution session is locked internally, making this function thread-safe.
        // The source is made defunct after transfer, which renders it unusable. It is the responsibility of the
        // API-user to release the resource tracker. So we let it go out of scope to automatically drop.
        // C++ source code:
        // [https://github.com/llvm/llvm-project/blob/2078da43e25a4623cab2d0d60decddf709aaea28/llvm/lib/ExecutionEngine/Orc/Core.cpp#L2213]
        // Documentation:
        // [https://llvm.org/doxygen/group__LLVMCExecutionEngineORC.html#ga344ed46e53d6f5bbeeb3786e73598115]
        unsafe { LLVMOrcResourceTrackerTransferTo(source.as_ptr(), self.as_ptr()); }
    }
}

impl Drop for ResourceTracker {
    fn drop(&mut self) {
        unsafe { LLVMOrcReleaseResourceTracker(self.as_ptr()) }
    }
}
