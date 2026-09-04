use ::core::{
    convert::Infallible,
    ffi::{CStr, c_char},
    mem::ManuallyDrop,
    ptr::{self, NonNull},
};

use ::std::borrow::Cow;

use ::llvm_sys::error::{
    LLVMConsumeError, LLVMDisposeErrorMessage, LLVMErrorRef, LLVMErrorTypeId, LLVMGetErrorMessage, LLVMGetErrorTypeId,
    LLVMOpaqueError,
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

/// An error message produced by [LLVMError]. This error message can not be expected to be valid utf-8, because it might
/// be constructed from a POSIX-path or some other sequence that contains near-arbitrary bytes (except for
/// nul-terminators).
#[repr(C)]
#[derive(Debug)]
pub struct LLVMErrorMessage {
    ptr: NonNull<c_char>,
    len: usize,
}
const _: () = crate::support::assert_niche::<LLVMErrorMessage>();

impl LLVMErrorMessage {
    /// Converts the error message into a raw c-string pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> *const c_char {
        self.ptr.as_ptr()
    }

    /// Returns the length of the error message.
    #[must_use]
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the sequence of raws bytes up until the nul-terminator.
    #[must_use]
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { ::core::slice::from_raw_parts(self.as_ptr().cast(), self.len) }
    }

    /// Returns the sequence of raw bytes that also contains the nul-terminator.
    #[must_use]
    #[inline(always)]
    pub fn as_bytes_with_nul(&self) -> &[u8] {
        unsafe { ::core::slice::from_raw_parts(self.as_ptr().cast(), self.len + 1) }
    }

    /// Produce a [CStr] from this error message.
    #[must_use]
    #[inline(always)]
    pub fn as_cstr(&self) -> &CStr {
        unsafe { CStr::from_bytes_with_nul_unchecked(self.as_bytes_with_nul()) }
    }

    /// Convert to a utf-8 string using a lossy operation.
    /// Since [LLVMErrorMessage] might be a non-utf8 string, it is necessary to build a lossy utf-8 string from it.
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.as_bytes())
    }
}

impl Drop for LLVMErrorMessage {
    fn drop(&mut self) {
        unsafe {
            LLVMDisposeErrorMessage(self.as_ptr().cast_mut());
        }
    }
}

// [https://llvm.org/doxygen/classllvm_1_1Error.html]
/// Internal LLVM error type with context and mandatory checking.
///
/// # NOTE
/// This is a transparent wrapper around a non-null version of [LLVMErrorRef].
#[repr(transparent)]
#[derive(Debug)]
pub struct LLVMError {
    ptr: NonNull<LLVMOpaqueError>,
}
const _: () = crate::support::assert_niche::<LLVMError>();

impl LLVMError {
    // REVIEW: Perhaps from_error_ref should be marked `unsafe`?
    /// Pass an [LLVMErrorRef] returned from an LLVM function. You do not need to perform a null check on the
    /// [LLVMErrorRef], this function does so for you, and returns `None` if it was null.
    pub fn from_error_ref(error: LLVMErrorRef) -> Option<Self> {
        NonNull::new(error).map(|ptr| Self { ptr })
    }

    /// Pass an [LLVMErrorRef] returned from an LLVM function. You do not need to perform a null check on the
    /// [LLVMErrorRef], this function does so for you, and returns [Ok] if it was null, and [Err] if there is an error.
    pub fn result_from_error_ref(error: LLVMErrorRef) -> Result<(), Self> {
        match Self::from_error_ref(error) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Returns the inner [LLVMErrorRef].
    ///
    /// # NOTE
    /// [LLVMErrorRef] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMErrorRef {
        self.ptr.as_ptr()
    }

    /// Consume the error, effectively ignoring it.
    ///
    /// This simply drops the [LLVMError], which calls [LLVMConsumeError].
    pub fn consume(self) {}

    /// Obtains the class ID of this error, or null if this is a success value.
    pub fn get_type_id(&self) -> LLVMErrorTypeId {
        unsafe { LLVMGetErrorTypeId(self.as_ptr()) }
    }

    /// Consume the error by turning it into an [LLVMErrorMessage].
    pub fn take_message(self) -> LLVMErrorMessage {
        unsafe {
            let error = ManuallyDrop::new(self);
            let cstr_ptr = LLVMGetErrorMessage(error.as_ptr());
            let Some(ptr) = NonNull::new(cstr_ptr) else {
                crate::support::panic_out_of_memory_error(file!(), line!(), "Could not get LLVMErrorMessage.")
            };
            let cstr = CStr::from_ptr(cstr_ptr);
            let len = cstr.count_bytes();
            LLVMErrorMessage { ptr, len }
        }
    }

    // TODO (ErisianArchitect): Determine if this function is even necessary.
    /// For operations that return an [LLVMError] but are expected to never fail, you should use this function to
    /// handle the returned error. This function will invoke a *panic* if there *is* a failure, so you should be mindful
    /// of how you utilize it. This is an alternative to [llvm_sys::LLVMCantFail], which would typically abort.
    ///
    /// # NOTE
    /// This function can panic if the [LLVMErrorRef] points to a failure.
    pub(crate) fn infallible(error_ref: LLVMErrorRef) {
        let Some(err) = Self::from_error_ref(error_ref) else {
            return;
        };
        let msg = err.take_message();
        let str_msg = msg.to_string_lossy();
        panic!(
            "Infallible operation was not infallible: {}\nFile: {}:{}",
            str_msg,
            file!(),
            line!()
        );
    }
}

impl Drop for LLVMError {
    fn drop(&mut self) {
        unsafe {
            LLVMConsumeError(self.as_ptr());
        }
    }
}
