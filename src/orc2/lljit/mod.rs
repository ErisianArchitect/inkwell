
pub mod builder;

use ::core::{
    ptr::{
        NonNull,
    },
};
use std::{ffi::CStr, fmt::Pointer};

use ::llvm_sys::{
    orc2::{
        lljit::{
            LLVMOrcLLJITRef,
            LLVMOrcOpaqueLLJIT,
            LLVMOrcDisposeLLJIT,
            LLVMOrcLLJITGetTripleString,
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

    /// Get this the target triple string for this [LLJIT].
    pub fn get_triple_string(&self) -> &str {
        // C API source.
        // [https://github.com/llvm/llvm-project/blob/dd8afce5797a6c638840ce17a9a5c6d88ae60d03/llvm/lib/ExecutionEngine/Orc/OrcV2CBindings.cpp#L957]
        // C API declaration source
        // [https://github.com/llvm/llvm-project/blob/dd8afce5797a6c638840ce17a9a5c6d88ae60d03/llvm/include/llvm-c/LLJIT.h#L150]
        // Documentation
        // [https://llvm.org/doxygen/group__LLVMCExecutionEngineLLJIT.html#ga3bd4b9f32cdb137fea4ac5652e65e762]
        unsafe {
            let triple_t_raw_cstr = LLVMOrcLLJITGetTripleString(self.as_ptr());
            if triple_t_raw_cstr.is_null() {
                panic!(
                    "Target Triple string returned from LLVMOrcLLJITGetTripleString was null.\nFile: {}:{}",
                    file!(),
                    line!(),
                );
            }
            let triple_t_cstr = CStr::from_ptr(triple_t_raw_cstr);
            let len = triple_t_cstr.count_bytes();
            let bytes = ::core::slice::from_raw_parts(triple_t_cstr.as_ptr().cast::<u8>(), len);
            // TODO: In theory, a target triple string should be exclusively ASCII, but this is unverified.
            str::from_utf8_unchecked(bytes)
        }
    }
}

impl Drop for LLJIT {
    fn drop(&mut self) {
        unsafe {
            // This should be an infallible operation. TODO: Check if it can fail on prior versions.
            // The [LLVMError] will drop on its own, and does not need to be handled.
            // [https://github.com/llvm/llvm-project/blob/dd8afce5797a6c638840ce17a9a5c6d88ae60d03/llvm/lib/ExecutionEngine/Orc/OrcV2CBindings.cpp#L944]
            if let Some(error) = LLVMError::from_error_ref(LLVMOrcDisposeLLJIT(self.as_ptr())) {
                let err_msg = error.take_message();
                let err_str = err_msg.to_string_lossy();
                panic!("Failed to drop LLJIT: {err_str}\nFile: {}:{}", file!(), line!());
            }
        }
    }
}
