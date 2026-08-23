
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
    ptr: NonNull<LLVMOrcOpaqueThreadSafeModule>,
}

impl ThreadSafeModule {
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
