
use ::core::{
    ptr::{
        NonNull,
    },
};

use ::llvm_sys::{
    error::{
        LLVMOpaqueError,
        LLVMErrorRef,
        LLVMConsumeError,
        LLVMErrorTypeId,
        LLVMGetErrorTypeId,
    },
};

/// Errors for operations involving alignment.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AlignmentError {
    #[error("{0} is not a power of two and cannot be used for alignment")]
    NonPowerOfTwo(u32),
    #[error("The src_align_bytes argument was not a power of two.")]
    SrcNonPowerOfTwo(u32),
    #[error("The dest_align_bytes argument was not a power of two.")]
    DestNonPowerOfTwo(u32),
    #[error(
        "Type is unsized and cannot be aligned. \
    Suggestion: Align memory manually."
    )]
    Unsized,
    #[error("Value is not an alloca, load, or store instruction.")]
    UnalignedInstruction,
}

/// The top-level Error type for the inkwell crate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Builder Error: {0}")]
    BuilderError(#[from] crate::builder::BuilderError),
    #[error("InstructionValue Error: {0}")]
    InstructionValueError(#[from] crate::values::InstructionValueError),
    #[error("Basic types must have names.")]
    EmptyNameError,
    #[error("Metadata is expected to be a node.")]
    GlobalMetadataError,
}

// [https://llvm.org/doxygen/classllvm_1_1Error.html]
/// Internal LLVM error type with context and mandatory checking.
/// 
/// NOTE: This is a transparent wrapper around a non-null version of [LLVMErrorRef].
#[repr(transparent)]
#[derive(Debug)]
pub struct LLVMError {
    ptr: NonNull<LLVMOpaqueError>,
}
const _: () = crate::support::assert_niche::<LLVMError>();

impl LLVMError {
    pub fn from_error_ref(error: LLVMErrorRef) -> Option<Self> {
        NonNull::new(error)
            .map(|ptr| Self { ptr })
    }

    /// Returns the inner [LLVMErrorRef].
    ///
    /// NOTE: [LLVMErrorRef] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMErrorRef {
        self.ptr.as_ptr()
    }

    /// Consume the error, effectively ignoring it.
    ///
    /// This simply drops the [LLVMError], which calls [LLVMConsumeError].
    pub fn consume(self) {}

    pub fn get_type_id(&self) -> LLVMErrorTypeId {
        unsafe {
            LLVMGetErrorTypeId(self.as_ptr())
        }
    }
}

impl Drop for LLVMError {
    fn drop(&mut self) {
        unsafe {
            LLVMConsumeError(self.as_ptr());
        }
    }
}
