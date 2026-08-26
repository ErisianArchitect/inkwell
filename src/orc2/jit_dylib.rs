
use ::core::{
    ptr::{
        self,
        NonNull,
    },
    marker::{
        PhantomData,
    },
};

use ::llvm_sys::{
    orc2::{
        LLVMOrcOpaqueJITDylib,
        LLVMOrcJITDylibRef,
    },
};

use crate::{
    orc2::{
        lljit::LLJIT,
    },
};

// TODO (ErisianArchitect): Documentation.
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct JITDylibRef<'lljit> {
    pub(crate) ptr: NonNull<LLVMOrcOpaqueJITDylib>,
    // JITDylib is owned by LLJIT
    // [https://llvm.org/docs/doxygen/llvm-c_2LLJIT_8h_source.html#l00144]
    pub(crate) _phantom: PhantomData<(&'lljit LLJIT,)>
}

impl<'lljit> JITDylibRef<'lljit> {
    /// Create a [JITDylibRef] instance from a raw [LLVMOrcJITDylibRef] without checking if it is null.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer is either null, or does not point to a valid
    /// [LLVMOrcJITDylibRef].
    #[must_use]
    #[inline(always)]
    pub unsafe fn from_raw_unchekced(ptr: LLVMOrcJITDylibRef) -> Self {
        Self {
            ptr: unsafe { NonNull::new_unchecked(ptr) },
            _phantom: PhantomData,
        }
    }

    /// Create a [JITDylibRef] instance from a raw [LLVMOrcJITDylibRef]. This function will only ensure that the
    /// pointer is non-null, it cannot verify that the reference is valid.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer does not point to a valid [LLVMOrcJITDylibRef].
    #[must_use]
    #[inline]
    pub unsafe fn from_raw(ptr: LLVMOrcJITDylibRef) -> Option<Self> {
        Some(Self {
            ptr: NonNull::new(ptr)?,
            _phantom: PhantomData,
        })
    }

    /// Returns the inner [LLVMOrcJITDylibRef].
    ///
    /// # NOTE
    /// [JitDylibRef] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcJITDylibRef {
        self.ptr.as_ptr()
    }
}
