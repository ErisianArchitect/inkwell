
use ::core::{
    ptr::{
        NonNull,
    },
};

use ::llvm_sys::{
    orc2::{
        LLVMOrcIndirectStubsManagerRef,
        LLVMOrcOpaqueIndirectStubsManager,
        LLVMOrcCreateLocalIndirectStubsManager,
        LLVMOrcDisposeIndirectStubsManager,
    },
};

// TODO (ErisianArchitect): IndirectStubsManager documentation.
#[repr(transparent)]
#[derive(Debug)]
pub struct IndirectStubsManager {
    ptr: NonNull<LLVMOrcOpaqueIndirectStubsManager>,
}

impl IndirectStubsManager {
    // TODO (ErisianArchitect): pub fn new

    /// Create an [IndirectStubsManager] instance from a raw [LLVMOrcIndirectStubsManagerRef] without checking if it is
    /// null.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer is either null, or does not point to a valid
    /// [LLVMOrcIndirectStubsManagerRef].
    #[must_use]
    #[inline(always)] // Zero-cost abstraction, inline(always) is fine.
    pub unsafe fn from_raw_unchecked(ptr: LLVMOrcIndirectStubsManagerRef) -> Self {
        unsafe {
            Self {
                ptr: NonNull::new_unchecked(ptr),
            }
        }
    }

    /// Create an [IndirectStubsManager] instance from a raw [LLVMOrcIndirectStubsManagerRef]. This function will only
    /// ensure that the pointer is non-null, it cannot verify that the reference is valid.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer does not point to a valid [LLVMOrcIndirectStubsManagerRef].
    #[must_use]
    #[inline]
    pub unsafe fn from_raw(ptr: LLVMOrcIndirectStubsManagerRef) -> Option<Self> {
        Some(Self {
            ptr: NonNull::new(ptr)?,
        })
    }

    /// Returns the inner [LLVMOrcIndirectStubsManagerRef].
    ///
    /// # NOTE
    /// [IndirectStubsManager] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcIndirectStubsManagerRef {
        self.ptr.as_ptr()
    }
}

impl Drop for IndirectStubsManager {
    fn drop(&mut self) {
        unsafe {
            LLVMOrcDisposeIndirectStubsManager(self.as_ptr());
        }
    }
}
