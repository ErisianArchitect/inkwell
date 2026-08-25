pub mod builder;

use ::core::{
    ptr::NonNull,
    ffi::{
        c_char,
    },
};
use std::{ffi::CStr, fmt::Pointer};

use ::llvm_sys::orc2::lljit::{
    LLVMOrcDisposeLLJIT, LLVMOrcLLJITGetTripleString, LLVMOrcLLJITRef, LLVMOrcOpaqueLLJIT,
    LLVMOrcLLJITGetGlobalPrefix,
    LLVMOrcLLJITGetMainJITDylib,
    LLVMOrcLLJITEnableDebugSupport,
    LLVMOrcLLJITGetObjectLinkingLayer,
    LLVMOrcLLJITGetExecutionSession,
    LLVMOrcLLJITGetIRTransformLayer,
    LLVMOrcLLJITGetObjTransformLayer,
    LLVMOrcLLJITGetDataLayoutStr,
    LLVMOrcLLJITAddObjectFile,
    LLVMOrcLLJITAddLLVMIRModule,
    LLVMOrcLLJITMangleAndIntern,
    LLVMOrcLLJITAddObjectFileWithRT,
    LLVMOrcLLJITAddLLVMIRModuleWithRT,
    LLVMOrcLLJITLookup,
};

use crate::error::LLVMError;

/// A high-level JIT (Just-In-Time) compiler utility built on top of LLVM's ORC (On-Request-Compilation) V2
/// architecture.
#[repr(transparent)]
#[derive(Debug)]
pub struct LLJIT {
    pub(crate) ptr: NonNull<LLVMOrcOpaqueLLJIT>,
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
            Self {
                ptr: NonNull::new_unchecked(ptr),
            }
        }
    }

    /// Create an [LLJIT] instance from a raw [LLVMOrcLLJITRef]. This function will only ensure that the pointer is
    /// non-null, it cannot verify that the reference is valid.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer does not point to a valid [LLVMOrcLLJITRef].
    #[must_use]
    #[inline]
    pub unsafe fn from_raw(ptr: LLVMOrcLLJITRef) -> Option<Self> {
        NonNull::new(ptr).map(|ptr| Self { ptr })
    }

    /// Returns the inner [LLVMOrcLLJITRef].
    ///
    /// # NOTE
    /// [LLJIT] is a transparent wrapper around this pointer.
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
            let triple_t_bytes = ::core::slice::from_raw_parts(triple_t_cstr.as_ptr().cast::<u8>(), len);
            // TODO (ErisianArchitect): In theory, a target triple string should be exclusively ASCII, but this is unverified.
            str::from_utf8_unchecked(triple_t_bytes)
        }
    }

    /// Returns the global prefix character according to the data layout of this [LLJIT].
    #[must_use]
    pub fn get_global_prefix(&self) -> c_char {
        // [https://llvm.org/doxygen/group__LLVMCExecutionEngineLLJIT.html#gaa7cb85ad57567365835f63b01eb9662e]
        unsafe {
            LLVMOrcLLJITGetGlobalPrefix(self.as_ptr())
        }
    }

    /// Get the data layout string for this [LLJIT] instance.
    pub fn get_data_layout_str(&self) -> &str {
        // Data layout strings appears to be all ASCII text. So it should be safe to interpret it as a utf-8 string.
        // [https://cnlelema.github.io/memo/en/compilers/llvm/data-layout/]
        // C API source code:
        // [https://llvm.org/doxygen/OrcV2CBindings_8cpp_source.html#l01179]
        // Documentation:
        // [https://llvm.org/doxygen/group__LLVMCExecutionEngineLLJIT.html#ga439fbf215a33566faac5d1cdecff89f4]
        // The string is borrowed, not owned.
        let data_layout_c_str = unsafe { LLVMOrcLLJITGetDataLayoutStr(self.as_ptr()) };
        assert!(
            !data_layout_c_str.is_null(),
            "LLVMOrcLLJITGetDataLayoutStr returned a null pointer, which is unexpected.",
        );
        // SAFETY: The above assertion already verified that it's non-null.
        let data_layout_c_str = unsafe {
            CStr::from_ptr(data_layout_c_str) };
            let byte_slice = unsafe { ::core::slice::from_raw_parts(
                data_layout_c_str.as_ptr().cast::<u8>(),
                data_layout_c_str.count_bytes(),
            )
        };
        match str::from_utf8(byte_slice) {
            Ok(data_layout_str) => data_layout_str,
            Err(err) => {
                panic!("LLVMOrcLLJITGetDataLayoutStr returned non-utf8 string.\n{err}");
            }
        }
    }
}

impl Drop for LLJIT {
    fn drop(&mut self) {
        unsafe {
            // TODO (ErisianArchitect): Check if it can fail on prior versions.
            // This should be an infallible operation.
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
