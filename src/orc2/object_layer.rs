
use ::core::{
    ptr::{
        NonNull,
    },
    marker::{
        PhantomData,
    },
};

use ::llvm_sys::{
    orc2::{
        LLVMOrcObjectLayerRef,
        LLVMOrcOpaqueObjectLayer,
        LLVMOrcDisposeObjectLayer,
    },
};

use crate::{
    orc2::{
        lljit::LLJIT,
    },
};

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectLayerImpl {
    pub(crate) ptr: NonNull<LLVMOrcOpaqueObjectLayer>,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectLayerRef<'lljit> {
    pub(crate) inner: ObjectLayerImpl,
    pub(crate) _phantom: PhantomData<(&'lljit LLJIT,)>,
}

#[repr(transparent)]
#[derive(Debug)]
pub struct ObjectLayer {
    pub(crate) inner: ObjectLayerImpl,
}

impl ObjectLayerImpl {
    /// Create an [ObjectLayerImpl] instance from a raw [LLVMOrcObjectLayerRef] without checking if it is null.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer is either null, or does not point to a valid
    /// [LLVMOrcObjectLayerRef].
    #[must_use]
    #[inline(always)]
    pub unsafe fn from_raw_unchecked(ptr: LLVMOrcObjectLayerRef) -> Self {
        Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        }
    }

    /// Create an [ObjectLayerImpl] instance from a raw [LLVMOrcObjectLayerRef]. This function will only ensure that the
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
    /// [ObjectLayerImpl] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcObjectLayerRef {
        self.ptr.as_ptr()
    }
}

impl<'lljit> ObjectLayerRef<'lljit> {
    /// Create an [ObjectLayerRef] instance from a raw [LLVMOrcObjectLayerRef] without checking if it is null.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer is either null, or does not point to a valid
    /// [LLVMOrcObjectLayerRef].
    #[must_use]
    #[inline(always)]
    pub unsafe fn from_raw_unchecked(ptr: LLVMOrcObjectLayerRef) -> Self {
        Self {
            inner: unsafe { ObjectLayerImpl::from_raw_unchecked(ptr) },
            _phantom: PhantomData,
        }
    }

    /// Create an [ObjectLayerRef] instance from a raw [LLVMOrcObjectLayerRef]. This function will only ensure that the
    /// pointer is non-null, it cannot verify that the reference is valid.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer does not point to a valid [LLVMOrcObjectLayerRef].
    #[must_use]
    #[inline]
    pub unsafe fn from_raw(ptr: LLVMOrcObjectLayerRef) -> Option<Self> {
        Some(Self {
            inner: unsafe { ObjectLayerImpl::from_raw(ptr)? },
            _phantom: PhantomData,
        })
    }

    /// Returns the inner [LLVMOrcObjectLayerRef].
    ///
    /// # NOTE
    /// [ObjectLayerRef] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcObjectLayerRef {
        self.inner.as_ptr()
    }
}

impl ObjectLayer {
    /// Create an [ObjectLayer] instance from a raw [LLVMOrcObjectLayerRef] without checking if it is null.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer is either null, or does not point to a valid
    /// [LLVMOrcObjectLayerRef].
    #[must_use]
    #[inline(always)]
    pub unsafe fn from_raw_unchecked(ptr: LLVMOrcObjectLayerRef) -> Self {
        Self {
            inner: unsafe { ObjectLayerImpl::from_raw_unchecked(ptr) },
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
            inner: unsafe { ObjectLayerImpl::from_raw(ptr)? },
        })
    }

    /// Returns the inner [LLVMOrcObjectLayerRef].
    ///
    /// # NOTE
    /// [ObjectLayer] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcObjectLayerRef {
        self.inner.as_ptr()
    }
}

impl<'lljit> std::ops::Deref for ObjectLayerRef<'lljit> {
    type Target = ObjectLayerImpl;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::Deref for ObjectLayer {
    type Target = ObjectLayerImpl;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for ObjectLayer {
    fn drop(&mut self) {
        unsafe { LLVMOrcDisposeObjectLayer(self.as_ptr()); }
    }
}
