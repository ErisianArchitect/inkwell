
use ::core::{
    ptr::{
        NonNull,
    },
};

use ::llvm_sys::{
    orc2::{
        LLVMOrcThreadSafeModuleRef,
        LLVMOrcOpaqueThreadSafeModule,
        LLVMOrcDisposeThreadSafeModule,
    },
};

#[repr(transparent)]
#[derive(Debug)]
pub struct ThreadSafeModule {
    pub(crate) ptr: NonNull<LLVMOrcOpaqueThreadSafeModule>,
}

impl ThreadSafeModule {
    
    /// Create an [ThreadSafeModule] instance from a raw [LLVMOrcThreadSafeModuleRef] without checking if it is null.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer is either null, or does not point to a valid
    /// [LLVMOrcThreadSafeModuleRef].
    pub fn from_raw_unchecked(ptr: LLVMOrcThreadSafeModuleRef) -> Self {
        unsafe {
            Self {
                ptr: NonNull::new_unchecked(ptr),
            }
        }
    }

    /// Create an [ThreadSafeModule] instance from a raw [LLVMOrcThreadSafeModuleRef]. This function will only
    /// ensure that the pointer is non-null, it cannot verify that the reference is valid.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer does not point to a valid [LLVMOrcThreadSafeModuleRef].
    pub fn from_raw(ptr: LLVMOrcThreadSafeModuleRef) -> Option<Self> {
        Some(Self {
            ptr: NonNull::new(ptr)?,
        })
    }
    
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcThreadSafeModuleRef {
        self.ptr.as_ptr()
    }
}

impl Drop for ThreadSafeModule {
    fn drop(&mut self) {
        unsafe {
            LLVMOrcDisposeThreadSafeModule(self.as_ptr());
        }
    }
}
