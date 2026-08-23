use ::core::ptr::NonNull;

use ::std::borrow::Cow;

use ::llvm_sys::orc2::{
    LLVMOrcCreateDumpObjects, LLVMOrcDisposeDumpObjects, LLVMOrcDumpObjectsRef, LLVMOrcOpaqueDumpObjects,
};

use crate::support::to_c_str;

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
        unsafe {
            Self {
                ptr: NonNull::new_unchecked(ptr),
            }
        }
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

    /// Returns the inner [LLVMOrcDumpObjectsRef].
    ///
    /// # NOTE
    /// [DumpObjects] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcDumpObjectsRef {
        self.ptr.as_ptr()
    }

    /// Create a new [DumpObjects].
    ///
    /// `dump_dir`: The directory path. If `None`, will default to the working directory.
    ///
    /// `identifier_override`: The file name stem to use when dumping objects. If this is `None`, then the identifier of
    /// each [MemoryBuffer] will be used (with a suffix of `.o`). If this is `Some`, the identifier will be used as a
    /// prefix with an appended counter with names such as `identifier.o`, `identifier.2.o`, `identifier.3.o`, etc.
    /// There should be no extension, as a `.o` suffix will be added.
    pub fn new(dump_dir: Option<&str>, identifier_override: Option<&str>) -> Self {
        unsafe {
            // C API source code
            // [https://github.com/llvm/llvm-project/blob/7e3217ca7c61d1eed7f092c46141c8c7a96ef19e/llvm/lib/ExecutionEngine/Orc/OrcV2CBindings.cpp#L876]
            // C API declaration source code
            // [https://github.com/llvm/llvm-project/blob/7e3217ca7c61d1eed7f092c46141c8c7a96ef19e/llvm/include/llvm-c/Orc.h#L1286]
            // Documentation
            // [https://llvm.org/doxygen/group__LLVMCExecutionEngineORC.html#ga27cbe5fbc27eb6880dc1fccffe017f33]
            let dump_dir = dump_dir.map(|d| to_c_str(d)).unwrap_or(Cow::Borrowed(c""));
            let identifier_override = identifier_override.map(|i| to_c_str(i)).unwrap_or(Cow::Borrowed(c""));
            let ptr = LLVMOrcCreateDumpObjects(dump_dir.as_ptr(), identifier_override.as_ptr());
            let Some(ptr) = NonNull::new(ptr) else {
                crate::support::panic_out_of_memory_error(file!(), line!(), "Unable to create DumpObjects instance.");
            };
            Self { ptr }
        }
    }
}

impl Drop for DumpObjects {
    fn drop(&mut self) {
        unsafe {
            LLVMOrcDisposeDumpObjects(self.as_ptr());
        }
    }
}
