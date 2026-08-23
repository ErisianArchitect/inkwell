
use ::core::{
    ptr::{
        NonNull,
    },
};

use ::llvm_sys::{
    orc2::{
        LLVMOrcDumpObjectsRef,
        LLVMOrcOpaqueDumpObjects,
        LLVMOrcCreateDumpObjects,
        LLVMOrcDisposeDumpObjects,
    },
};

#[repr(transparent)]
#[derive(Debug)]
pub struct DumpObjects {
    ptr: NonNull<LLVMOrcOpaqueDumpObjects>,
}

impl DumpObjects {
    /// Create an [DumpObjects] instance from a raw [LLVMOrcDumpObjectsRef] without checking if it is null.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer is either null, or does not point to a valid
    /// [LLVMOrcDumpObjectsRef].
    pub unsafe fn from_raw_unchecked(ptr: LLVMOrcDumpObjectsRef) -> Self {
        unsafe { Self { ptr: NonNull::new_unchecked(ptr) } }
    }

    /// Create an [DumpObjects] instance from a raw [LLVMOrcDumpObjectsRef]. This function will only ensure that the
    /// pointer is non-null, it cannot verify that the reference is valid.
    ///
    /// # Safety
    /// Will cause Undefined Behavior if the pointer does not point to a valid [LLVMOrcDumpObjectsRef].
    pub unsafe fn from_raw(ptr: LLVMOrcDumpObjectsRef) -> Option<Self> {
        Some(Self {
            ptr: NonNull::new(ptr)?,
        })
    }
}

impl Drop {
    fn drop(&mut self) {
        unsafe {
            LLVMOrcDisposeDumpObjects(self.as_ptr());
        }
    }
}
