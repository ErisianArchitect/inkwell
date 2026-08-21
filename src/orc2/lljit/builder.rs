use ::core::{
    ptr::{
        NonNull,
    },
    mem::{
        ManuallyDrop,
    },
};

use ::llvm_sys::{
    orc2::lljit::{
        LLVMOrcCreateLLJIT,
        LLVMOrcCreateLLJITBuilder,
        LLVMOrcDisposeLLJITBuilder,
        LLVMOrcLLJITBuilderRef,
        LLVMOrcOpaqueLLJITBuilder,
        LLVMOrcLLJITBuilderSetJITTargetMachineBuilder,
    },
};

use crate::{
    orc2::{
        target_machine::{
            JITTargetMachineBuilder,
        },
    },
};

/// A [NonNull] variant that wraps [LLVMOrcOpaqueLLJITBuilder], which is the equivalent of a non-null
/// [LLVMOrcLLJITBuilderRef].
pub type LLJITBuilderRefNonNull = NonNull<LLVMOrcOpaqueLLJITBuilder>;

/// A builder that is used to construct either an [LLJIT] or [LLLazyJIT] instance.
#[repr(transparent)]
#[derive(Debug)]
pub struct LLJITBuilder {
    ptr: LLJITBuilderRefNonNull,
}
const _: () = crate::support::assert_niche::<LLJITBuilder>();

/* STRUCT LLJITBuilder:
Important Functions:
create ------------: Create a new [LLJITBuilder].
as_ptr ------------: Convert the [LLJITBuilder] instance into an [LLVMOrcLLJITBuilderRef].
*/
impl LLJITBuilder {
    /// Create an [LLJITBuilder], which can be used to construct an [LLJIT] instance.
    pub fn create() -> Self {
        unsafe {
            let Some(ptr) = NonNull::new(LLVMOrcCreateLLJITBuilder()) else {
                crate::support::panic_out_of_memory_error(file!(), line!(), "Unable to create LLJITBuilder.");
            };
            Self { ptr }
        }
    }
    
    /// Returns the inner [LLVMOrcLLJITBuilderRef].
    ///
    /// NOTE: [LLJITBuilder] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcLLJITBuilderRef {
        // NOTE: LLJITBuilder isn't usable in const contexts at this time, so there's no reason to make this function
        //       const.
        self.ptr.as_ptr()
    }

    /// Set the [JITTargetMachineBuilder] for creation of the LLJIT instance.
    ///
    /// This function is optional, and by omitting it, [LLJITBuilder] will use [JITTargetMachineBuilder::detect_host]
    /// instead.
    pub fn set_target_machine_builder(&mut self, builder: JITTargetMachineBuilder) {
        let builder = ManuallyDrop::new(builder);
        unsafe {
            LLVMOrcLLJITBuilderSetJITTargetMachineBuilder(self.as_ptr(), builder.as_ptr());
        }
    }

}

impl Drop for LLJITBuilder {
    fn drop(&mut self) {
        unsafe {
            LLVMOrcDisposeLLJITBuilder(self.as_ptr());
        }
    }
}

/* --- | NOTES
LLJITBuilder is a factory/builder that is used to construct an LLJIT or an LLLazyJIT.
When an LLJIT is created from an LLJITBuilder, the LLJIT, I believe, takes ownership of the LLJITBuilder,
and LLVMOrcDisposeLLJITBuilder should not be called.
LLVMErrorRef is something that is used in this API, and some implementation of LLVMErrorRef exists in
<src/execution_engine.rs:593>
*/
