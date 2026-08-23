
pub mod builder;

use ::core::{
    ptr::{
        NonNull,
    },
};

use ::llvm_sys::{
    orc2::{
        lljit::{
            LLVMOrcLLJITRef,
            LLVMOrcOpaqueLLJIT,
            LLVMOrcDisposeLLJIT,
        },
    },
};

use crate::{
    error::{
        LLVMError,
    },
};

/// A high-level JIT (Just-In-Time) compiler utility built on top of LLVM's ORC (On-Request-Compilation) V2
/// architecture.
#[repr(transparent)]
#[derive(Debug)]
pub struct LLJIT {
    ptr: NonNull<LLVMOrcOpaqueLLJIT>,
}

impl LLJIT {
    /// Create an [LLJIT] instance from a raw [LLVMOrcLLJITRef] without checking if it is null.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer is either null, or does not point to a valid [LLVMOrcLLJITRef].
    #[must_use]
    #[inline(always)] // Zero-cost abstraction, fine to use inline(always)
    pub unsafe fn from_raw_unchecked(ptr: LLVMOrcLLJITRef) -> Self {
        unsafe {
            Self { ptr: NonNull::new_unchecked(ptr) }
        }
    }

    /// Create an [LLJIT] instance from a raw [LLVMOrcLLJITRef]. This function will only ensure that the pointer is
    /// non-null, it cannot verify that the reference is valid.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer does not point to a valid [LLVMOrcLLJITRef].
    #[must_use]
    #[inline(always)] // Zero-cost abstraction, fine to use inline(always)
    pub unsafe fn from_raw(ptr: LLVMOrcLLJITRef) -> Option<Self> {
        NonNull::new(ptr).map(|ptr| Self { ptr })
    }

    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcLLJITRef {
        self.ptr.as_ptr()
    }
}

impl Drop for LLJIT {
    fn drop(&mut self) {
        unsafe {
            // This is an infallible operation.
            // The [LLVMError] will drop on its own, and does not need to be handled.
            // [https://github.com/llvm/llvm-project/blob/dd8afce5797a6c638840ce17a9a5c6d88ae60d03/llvm/lib/ExecutionEngine/Orc/OrcV2CBindings.cpp#L944]
            LLVMError::from_error_ref(LLVMOrcDisposeLLJIT(self.as_ptr()));
        }
    }
}
