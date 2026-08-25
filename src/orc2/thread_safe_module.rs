
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

/// A utility struct that stores a [FnOnce] closure, and receives the return value of the function.
/// The return value that is stored in a `Result<R, Box<dyn Any + Send + 'static>>`. The error is a [catch_unwind] panic
/// payload. [ThreadSafeModule::with_module_do] will resume the panic if the return value is `Err(payload)`.
pub(crate) struct IrModuleOperation<F: for<'ctx> FnOnce(&mut Module<'ctx>) -> R + UnwindSafe, R> {
    pub(crate) func: Option<F>,
    pub(crate) return_value: Option<Result<R, Box<dyn Any + Send + 'static>>>,
}

/// The callback used by [ThreadSafeModule::with_module_do] to mutate the inner [Module].
///
/// This callback takes a `*mut c_void` which is then converted into an `&mut IRModuleOperation<F, R>`. This
/// [IRModuleOperation] contains a [FnOnce] callback, and a storage slot for the return value.
///
/// If the callback in the [IRModuleOperation] panics when it is called, the panic will be caught with [catch_unwind].
/// The payload of that panic is assigned to the `Err` slot of the `return_value` field of [IRModuleOperation].
///
/// Whatever function uses this callback must choose what to do with the [catch_unwind] panic payload. The recommended
/// action is [resume_unwind].
///
/// # Safety:
/// This callback expectes that `ctx` points to valid [IrModuleOperator] with the same generics as this function.
pub(crate) extern "C" fn generic_ir_module_operation<
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
    pub unsafe fn from_raw_unchecked(ptr: LLVMOrcThreadSafeModuleRef) -> Self {
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
    pub unsafe fn from_raw(ptr: LLVMOrcThreadSafeModuleRef) -> Option<Self> {
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
    ///
    /// The closure must be [UnwindSafe]. It is possible to force this constraint with [AssertUnwindSafe], but it is not
    /// recommended.
    ///
    /// [AssertUnwindSafe]: std::panic::AssertUnwindSafe
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
            // This result should always be null. According to the LLVM source code, it wouldn't make sense for it to be
            // non-null, as the error is user provided, and we aren't providing an error value
            // (`generic_ir_module_operation` returns null_mut).
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
