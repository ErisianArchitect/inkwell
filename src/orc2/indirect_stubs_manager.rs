
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

use crate::{
    targets::{
        TargetTriple,
    },
};

// TODO (ErisianArchitect): IndirectStubsManager documentation.
#[repr(transparent)]
#[derive(Debug)]
pub struct IndirectStubsManager {
    pub(crate) ptr: NonNull<LLVMOrcOpaqueIndirectStubsManager>,
}

impl IndirectStubsManager {
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

    /// Create an [IndirectStubsManager] from a target triple.
    #[must_use]
    pub fn new(target_triple: &TargetTriple) -> Self {
        unsafe {
            // C API source code:
            // [https://llvm.org/doxygen/OrcV2CBindings_8cpp_source.html#l01184]
            // Documentation:
            // [https://llvm.org/doxygen/group__LLVMCExecutionEngineORC.html#ga7b78931cda11ac9d05a701dc8a28f13b]
            let ptr = LLVMOrcCreateLocalIndirectStubsManager(target_triple.as_ptr());
            let Some(ptr) = NonNull::new(ptr) else {
                crate::support::panic_out_of_memory_error(file!(), line!(), "Unable to create IndirectStubsManager.");
            }
            Self {
                ptr,
            }
        }
    }
}

impl Drop for IndirectStubsManager {
    fn drop(&mut self) {
        unsafe {
            LLVMOrcDisposeIndirectStubsManager(self.as_ptr());
        }
    }
}
