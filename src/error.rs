use std::{ffi::CStr, sync::Arc};

use llvm_sys::error::{LLVMDisposeErrorMessage, LLVMGetErrorMessage, LLVMOpaqueError};

// TODO: Update these OrcError imports when new versions of LLVM are added.
//       Right now, it is known to support up to llvm20-1, but in the future the import might be different if
//       LLVM Orc V3 is ever created.
#[llvm_versions(..=11)]
use crate::orc::error::OrcError;
#[llvm_versions(11..=20.1)]
use crate::orc2::error::Orc2Error;


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
    #[cfg(any(
        // TODO: When additional prior llvm versions are supported that contain the Orc API, update this cfg attribute.
        feature = "llvm8-0",
        feature = "llvm9-0",
        feature = "llvm10-0",
        feature = "llvm11-0",
    ))]
    #[error("OrcError: {0}")]
    OrcError(#[from] OrcError),
    #[cfg(any(
        feature = "llvm11-0",
        feature = "llvm12-0",
        feature = "llvm13-0",
        feature = "llvm14-0",
        feature = "llvm15-0",
        feature = "llvm16-0",
        feature = "llvm17-0",
        feature = "llvm18-1",
        feature = "llvm19-1",
        feature = "llvm20-1",
        // TODO: When additional future llvm versions are supported that contain the Orc2 API, update this cfg attribute.
    ))]
    #[error("Orc2Error: {0}")]
    Orc2Error(#[from] Orc2Error),
}

struct LLVMErrorStringInner {
    cstr: *mut i8,
    len: usize,
}

impl LLVMErrorStringInner {
    #[cfg_attr(debug_assertions, track_caller)]
    #[inline]
    pub(crate) fn to_str(&self) -> &str {
        debug_assert!(!self.cstr.is_null(), "self.cstr must not be null.");
        let bytes = unsafe { std::slice::from_raw_parts(self.cstr as _, self.len) };
        // SAFETY: As long as the C string came from LLVM, it will be valid UTF-8.
        unsafe { str::from_utf8_unchecked(bytes) }
    }

    #[cfg_attr(debug_assertions, track_caller)]
    #[inline]
    pub(crate) fn to_cstr(&self) -> &CStr {
        debug_assert!(!self.cstr.is_null(), "self.cstr must not be null.");
        let bytes = unsafe {
            std::slice::from_raw_parts(self.cstr as _, self.len + 1 /* add 1 for the null terminator */)
        };
        // SAFETY: `self.inner.cstr` is ensured to be non-null, and is always a C style string when it
        //         comes from LLVMGetErrorMessage.
        unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
    }
}

// TODOC (ErisianArchitect): struct LLVMErrorString
#[derive(Clone)]
pub struct LLVMErrorString {
    inner: Arc<LLVMErrorStringInner>,
}

// TODOC (ErisianArchitect): impl LLVMErrorString
impl LLVMErrorString {
    /// Creates an [LLVMErrorString] from a pointer to [LLVMOpaqueError]. The pointer must not be null, otherwise the function will panic.
    #[cfg_attr(debug_assertions, track_caller)]
    #[must_use]
    pub(crate) unsafe fn new(opaque: *mut LLVMOpaqueError) -> Self {
        debug_assert!(!opaque.is_null(), "opaque: *mut LLVMOpaqueError cannot be null.");
        // cstr will always be non-null if opaque is non-null and comes from LLVM.
        let cstr = LLVMGetErrorMessage(opaque);
        debug_assert!(!cstr.is_null(), "Returned error message was null.");
        let len = libc::strlen(cstr);
        Self {
            inner: Arc::new(LLVMErrorStringInner {
                cstr,
                len,
            })
        }
    }
    
    /// Gets the length of the memory buffer of the error message string. This is the string length + 1 for the null terminator (`\0`).
    #[must_use]
    #[inline]
    pub fn buffer_length(&self) -> usize {
        self.inner.len + 1
    }

    /// Converts the [LLVMErrorString] into a [str].
    #[cfg_attr(debug_assertions, track_caller)]
    #[must_use]
    #[inline]
    pub fn to_str(&self) -> &str {
        self.inner.to_str()
    }

    /// Converts the [LLVMErrorString] into a [CStr].
    #[cfg_attr(debug_assertions, track_caller)]
    #[must_use]
    #[inline]
    pub fn to_cstr(&self) -> &CStr {
        self.inner.to_cstr()
    }
}

impl AsRef<str> for LLVMErrorString {
    #[inline]
    fn as_ref(&self) -> &str {
        self.to_str()
    }
}

impl AsRef<CStr> for LLVMErrorString {
    #[inline]
    fn as_ref(&self) -> &CStr {
        self.to_cstr()
    }
}

impl std::borrow::Borrow<str> for LLVMErrorString {
    #[inline]
    fn borrow(&self) -> &str {
        self.to_str()
    }
}

impl std::borrow::Borrow<CStr> for LLVMErrorString {
    #[inline]
    fn borrow(&self) -> &CStr {
        self.to_cstr()
    }
}

impl PartialEq<LLVMErrorString> for LLVMErrorString {
    fn eq(&self, other: &LLVMErrorString) -> bool {
        std::ptr::eq(self.inner.cstr, other.inner.cstr) || self.to_str() == other.to_str()
    }
    
    fn ne(&self, other: &LLVMErrorString) -> bool {
        !std::ptr::eq(self.inner.cstr, other.inner.cstr) && self.to_str() != other.to_str()
    }
}

impl Eq for LLVMErrorString {}

impl PartialEq<str> for LLVMErrorString {
    fn eq(&self, other: &str) -> bool {
        self.to_str() == other
    }

    fn ne(&self, other: &str) -> bool {
        self.to_str() != other
    }
}

impl PartialEq<CStr> for LLVMErrorString {
    fn eq(&self, other: &CStr) -> bool {
        std::ptr::eq(self.inner.cstr, other.as_ptr()) || self.to_cstr() == other
    }

    fn ne(&self, other: &CStr) -> bool {
        !std::ptr::eq(self.inner.cstr, other.as_ptr()) && self.to_cstr() != other
    }
}

impl std::fmt::Display for LLVMErrorString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl std::fmt::Debug for LLVMErrorString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_str())
    }
}

impl std::error::Error for LLVMErrorString {
    fn description(&self) -> &str {
        self.to_str()
    }
}

impl Drop for LLVMErrorStringInner {
    fn drop(&mut self) {
        unsafe { LLVMDisposeErrorMessage(self.cstr); }
    }
}