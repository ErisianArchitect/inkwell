use ::core::{
    mem::ManuallyDrop,
    ptr::{self, NonNull},
};

use ::llvm_sys::orc2::lljit::{
    LLVMOrcCreateLLJIT, LLVMOrcCreateLLJITBuilder, LLVMOrcDisposeLLJITBuilder, LLVMOrcLLJITBuilderRef,
    LLVMOrcLLJITBuilderSetJITTargetMachineBuilder, LLVMOrcOpaqueLLJITBuilder,
};

use crate::{
    error::LLVMError,
    orc2::{lljit::LLJIT, target_machine_builder::JITTargetMachineBuilder},
};

/// A builder that is used to construct either an [LLJIT].
#[repr(transparent)]
#[derive(Debug)]
pub struct LLJITBuilder {
    ptr: NonNull<LLVMOrcOpaqueLLJITBuilder>,
}
const _: () = crate::support::assert_niche::<LLJITBuilder>();

impl LLJITBuilder {
    /// Unchecked creation of an [LLJITBuilder] from an [LLVMOrcLLJITBuilderRef].
    ///
    /// # Safety
    /// This function produces an unchecked [NonNull] from the pointer that is provided, which can cause undefined
    /// behavior if it is null or does not point to a valid LLJITBuilder.
    #[must_use]
    #[inline(always)] // zero-cost abstractions, fine to mark as inline(always).
    pub unsafe fn from_raw_unchecked(ptr: LLVMOrcLLJITBuilderRef) -> Self {
        unsafe {
            Self {
                ptr: NonNull::new_unchecked(ptr),
            }
        }
    }

    /// Attempt to create an [LLJITBuilder] from a raw pointer.
    ///
    /// # Safety
    /// This function assumes that the pointer provided is a valid reference to [LLVMOrcLLJITBuilder].
    #[must_use]
    #[inline(always)] // zero-cost abstractions, fine to mark as inline(always).
    pub unsafe fn from_raw(ptr: LLVMOrcLLJITBuilderRef) -> Option<Self> {
        NonNull::new(ptr).map(|ptr| Self { ptr })
    }

    /// Create an [LLJITBuilder], which can be used to construct an [LLJIT] instance.
    ///
    /// # Example
    /// ```rust
    /// use inkwell::orc2::lljit::builder::LLJITBuilder;
    /// let builder = LLJITBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
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
        // LLVMOrcLLJITBuilderSetJITTargetMachineBuilder takes ownership of JITTargetMachineBuilder.
        // [https://llvm.org/docs/doxygen/group__LLVMCExecutionEngineLLJIT.html#gabc2878deee51f35abc19ba2fc28ce4cf]
        let builder = ManuallyDrop::new(builder);
        unsafe {
            LLVMOrcLLJITBuilderSetJITTargetMachineBuilder(self.as_ptr(), builder.as_ptr());
        }
    }

    /// Attempts to create an [LLJIT] instance by consuming this [LLJITBuilder].
    pub fn build(self) -> Result<LLJIT, LLVMError> {
        // Creating the LLJIT instance from the builder takes ownership of the builder regardless of success status.
        // [https://llvm.org/doxygen/group__LLVMCExecutionEngineLLJIT.html#gade2e259b9be0f749666842ada250a816]
        let mut ptr = ptr::null_mut();
        let builder = ManuallyDrop::new(self);
        let result = unsafe { LLVMError::from_error_ref(LLVMOrcCreateLLJIT(&mut ptr, builder.as_ptr())) };
        if let Some(error) = result {
            return Err(error);
        }
        let Some(ptr) = NonNull::new(ptr) else {
            crate::support::panic_out_of_memory_error(file!(), line!(), "Unable to create LLJIT from LLJITBuilder");
        };
        Ok(LLJIT { ptr })
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
