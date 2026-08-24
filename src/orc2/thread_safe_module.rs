
use ::core::{
    ptr::{
        self,
        NonNull,
    },
    mem::{
        ManuallyDrop,
    },
    ffi::{
        c_void,
    },
};

use ::std::{
    any::{Any},
    panic::{
        catch_unwind,
        resume_unwind,
        UnwindSafe,
    },
};

use ::llvm_sys::{
    prelude::{
        LLVMModuleRef,
    },
    error::{
        LLVMErrorRef,
    },
    orc2::{
        LLVMOrcThreadSafeModuleRef,
        LLVMOrcOpaqueThreadSafeModule,
        LLVMOrcDisposeThreadSafeModule,
        LLVMOrcThreadSafeModuleWithModuleDo,
    },
};

use crate::{
    module::{Module},
};

pub(crate) struct IrModuleOperation<F: for<'ctx> FnOnce(&mut Module<'ctx>) -> R + UnwindSafe, R> {
    pub(crate) func: Option<F>,
    pub(crate) return_value: Option<Result<R, Box<dyn Any + Send + 'static>>>,
}

extern "C" fn generic_ir_module_operation<
    // Ferris bless the Rust Project for generic extern "C" functions.
    F: for<'ctx> FnOnce(&mut Module<'ctx>) -> R + UnwindSafe,
    R,
>(ctx: *mut c_void, module: LLVMModuleRef) -> LLVMErrorRef {
    // IMPORTANT: You cannot panic in this function, because it returns control to LLVM.
    //            Panicking here would be undefined behavior.
    // SAFETY: LLVMModuleRef is coming directly from LLVM, and should be a valid pointer.
    let mut module = ManuallyDrop::new(unsafe { Module::new(module) });
    // SAFETY: Only a valid pointer will ever be passed to this function.
    let callback = unsafe { ctx.cast::<IrModuleOperation<F, R>>().as_mut_unchecked() };
    // In practice, this will never be None.
    if let Some(func) = callback.func.take() {
        let unwind_result = catch_unwind(move || {
            func(&mut module)
        });
        callback.return_value = Some(unwind_result);
    }
    // We aren't using LLVMError, it's not necessary, and only complicates the API.
    // [https://llvm.org/doxygen/ThreadSafeModule_8h_source.html#l00113]
    // [https://llvm.org/doxygen/OrcV2CBindings_8cpp_source.html#l00744]
    ptr::null_mut()
}

impl<F: for<'ctx> FnOnce(&mut Module<'ctx>) -> R + UnwindSafe, R> IrModuleOperation<F, R> {
    pub(crate) fn new(func: F) -> Self {
        Self {
            func: Some(func),
            return_value: None,
        }
    }
}

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

    /// Mutate the inner [Module] using a closure.
    pub fn with_module_do<
        R,
        F: for<'ctx> FnOnce(&mut Module<'ctx>) -> R + UnwindSafe
    >(&self, f: F) -> R {
        // Function provided is called exactly once.
        // C++ API source code:
        // [https://llvm.org/doxygen/ThreadSafeModule_8h_source.html#l00113]
        // C API source code:
        // [https://llvm.org/doxygen/OrcV2CBindings_8cpp_source.html#l00744]
        // Documentation:
        // [https://llvm.org/doxygen/group__LLVMCExecutionEngineORC.html#ga91c2fe589434e8b16812b5e8d42cf9c6]
        let mut op = IrModuleOperation::new(f);
        unsafe {
            // This result should not ever be non-null. According to the LLVM source code, that wouldn't make sense.
            let result = LLVMOrcThreadSafeModuleWithModuleDo(
                self.as_ptr(),
                generic_ir_module_operation::<F, R>,
                // I know this looks weird, but the second cast is necessary.
                &mut op as *mut _ as *mut _,
            );
            assert!(result.is_null(), "LLVMError was not null, which is unexpected.\nFile: {}:{}", file!(), line!());
            let Some(result) = op.return_value else {
                // If this error occurs, that means that the code that was supposed to set the return_value was
                // modified. Or otherwise something that I couldn't anticipate has happened.
                panic!("Return value was None, which is unexpected.\nFile: {}:{}", file!(), line!());
            };
            match result {
                Ok(return_value) => return_value,
                Err(payload) => resume_unwind(payload),
            }
        }
    }
}

unsafe impl Send for ThreadSafeModule {}
unsafe impl Sync for ThreadSafeModule {}

impl Drop for ThreadSafeModule {
    fn drop(&mut self) {
        unsafe {
            LLVMOrcDisposeThreadSafeModule(self.as_ptr());
        }
    }
}
