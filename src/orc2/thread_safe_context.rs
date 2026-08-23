
use ::core::{
    ptr::{
        NonNull,
    },
};

use ::llvm_sys::{
    orc2::{
        LLVMOrcThreadSafeContextRef,
        LLVMOrcOpaqueThreadSafeContext,
        LLVMOrcCreateNewThreadSafeContext,
        LLVMOrcCreateNewThreadSafeContextFromLLVMContext,
        LLVMOrcDisposeThreadSafeContext,
        LLVMOrcCreateNewThreadSafeModule,
    },
};



// TODO (ErisianArchitect): ThreadSafeContext documentation.
#[repr(transparent)]
#[derive(Debug)]
pub struct ThreadSafeContext {
    ptr: NonNull<LLVMOrcOpaqueThreadSafeContext>,
}

impl ThreadSafeContext {
    /// Create an [ThreadSafeContext] instance from a raw [LLVMOrcThreadSafeContextRef] without checking if it is null.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer is either null, or does not point to a valid
    /// [LLVMOrcThreadSafeContextRef].
    #[must_use]
    #[inline(always)] // Zero-cost abstraction, inline(always) is fine.
    pub unsafe fn from_raw_unchecked(ptr: LLVMOrcThreadSafeContextRef) -> Self {
        unsafe {
            Self {
                ptr: NonNull::new_unchecked(ptr),
            }
        }
    }

    /// Create an [ThreadSafeContext] instance from a raw [LLVMOrcThreadSafeContextRef]. This function will only
    /// ensure that the pointer is non-null, it cannot verify that the reference is valid.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer does not point to a valid [LLVMOrcThreadSafeContextRef].
    #[must_use]
    #[inline]
    pub unsafe fn from_raw(ptr: LLVMOrcThreadSafeContextRef) -> Option<Self> {
        Some(Self {
            ptr: NonNull::new(ptr)?,
        })
    }

    /// Returns the inner [LLVMOrcThreadSafeContextRef].
    ///
    /// # NOTE
    /// [ThreadSafeContext] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcThreadSafeContextRef {
        self.ptr.as_ptr()
    }

    /// Create a new [ThreadSafeContext].
    #[must_use]
    pub fn new() -> Self {
        // LLVM C API source code:
        // [https://llvm.org/doxygen/OrcV2CBindings_8cpp_source.html#l00730]
        // Documentation:
        // [https://llvm.org/doxygen/group__LLVMCExecutionEngineORC.html#gac4b118d616f60a713ed74641272ba150]
        unsafe {
            let ptr = LLVMOrcCreateNewThreadSafeContext();
            let Some(ptr) = NonNull::new(ptr) else {
                crate::support::panic_out_of_memory_error(file!(), line!(), "Unable to create ThreadSafeContext.");
            };
            Self {
                ptr,
            }
        }
    }
}

impl Drop for ThreadSafeContext {
    fn drop(&mut self) {
        unsafe {
            LLVMOrcDisposeThreadSafeContext(self.as_ptr());
        }
    }
}
