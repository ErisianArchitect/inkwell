
use ::core::{
    ptr::{
        NonNull,
    },
};

use ::llvm_sys::{
    orc2::{
        LLVMOrcObjectLayerRef,
        LLVMOrcOpaqueObjectLayer,
        LLVMOrcDisposeObjectLayer,
    },
},

#[derive(Debug)]
pub struct ObjectLayer {
    pub(crate) ptr: NonNull<LLVMOrcOpaqueObjectLayer>,
}

impl ObjectLayer {
    /// Create an [ObjectLayer] instance from a raw [LLVMOrcObjectLayerRef] without checking if it is null.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer is either null, or does not point to a valid
    /// [LLVMOrcObjectLayerRef].
    #[must_use]
    #[inline(always)]
    pub unsafe fn from_raw_unchekced(ptr: LLVMOrcObjectLayerRef) -> Self {
        Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        }
    }

    /// Create an [ObjectLayer] instance from a raw [LLVMOrcObjectLayerRef]. This function will only ensure that the
    /// pointer is non-null, it cannot verify that the reference is valid.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer does not point to a valid [LLVMOrcObjectLayerRef].
    #[must_use]
    #[inline]
    pub unsafe fn from_raw(ptr: LLVMOrcObjectLayerRef) -> Option<Self> {
        Some(Self {
            ptr: NonNull::new(ptr)?,
        })
    }

    /// Returns the inner [LLVMOrcObjectLayerRef].
    ///
    /// # NOTE
    /// [ObjectLayer] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcObjectLayerRef {
        self.ptr.as_ptr()
    }
}

impl Drop for ObjectLayer {
    fn drop(&mut self) {
        unsafe { LLVMOrcDisposeObjectLayer(self.as_ptr()); }
    }
}
