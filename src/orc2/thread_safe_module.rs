
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

/// A sort of state machine for [IRModuleOperation].
#[derive(Debug)]
pub(crate) enum IRModuleOpState<
    F: for<'ctx> FnOnce(&mut Module<'ctx>) -> R,
    R,
> {
    /// The inner value was taken, but nothing was put back.
    Taken,
    /// This is the intended initial state.
    Func(F),
    /// This is where the return value for the `Func` variant is stored.
    Return(R),
    /// If a panic occurs in the non-panicking `generic_ir_module_operation` function, it will end up here.
    Panic(Box<dyn Any + Send + 'static>),
    /// The [IRModuleOpState::Func] variant was expected, but the value encountered was a different variant.
    MissingFunc,
}

impl<F: for<'ctx> FnOnce(&mut Module<'ctx>) -> R, R> IRModuleOpState<F, R> {
    #[must_use]
    pub fn take(&mut self) -> Self {
        ::core::mem::replace(self, Self::Taken)
    }
}

/// A utility struct that stores a [FnOnce] closure, and receives the return value of the function.
/// The return value that is stored in a `Result<R, Box<dyn Any + Send + 'static>>`. The error is a [catch_unwind] panic
/// payload. [ThreadSafeModule::with_module_do] will resume the panic if the return value is `Err(payload)`.
#[derive(Debug)]
pub(crate) struct IRModuleOperation<F: for<'ctx> FnOnce(&mut Module<'ctx>) -> R + UnwindSafe, R> {
    pub(crate) state: IRModuleOpState<F, R>,
}

/// The callback used by [ThreadSafeModule::with_module_do] to mutate the inner [Module].
///
/// This callback takes a `*mut c_void` which is then converted into an `&mut IRModuleOperation<F, R>`. This
/// [IRModuleOperation] is initialized with the [FnOnce] callback.
///
/// If the callback in the [IRModuleOperation] panics when it is called, the panic will be caught with [catch_unwind].
/// The payload of that panic is assigned to the `state` field of [IRModuleOperation] as [IRModuleOpState::Panic].
///
/// Whatever function uses this callback must choose what to do with the [catch_unwind] panic payload. The recommended
/// action is [resume_unwind].
///
/// # Safety:
/// This callback expects that `ctx` points to valid [IrModuleOperator] with the same generics as this function.
pub(crate) extern "C" fn generic_ir_module_operation<
    // Ferris bless the Rust Project for generic extern "C" functions.
    F: for<'ctx> FnOnce(&mut Module<'ctx>) -> R + UnwindSafe,
    R,
>(ctx: *mut c_void, module: LLVMModuleRef) -> LLVMErrorRef {
    // IMPORTANT: You cannot panic in this function, because it returns control to LLVM.
    //            Panicking here would be undefined behavior.
    // SAFETY: Only a valid pointer should ever be passed to this function.
    let callback = unsafe { ctx.cast::<IRModuleOperation<F, R>>().as_mut_unchecked() };
    // Module::new can panic, so we have to anticipate that happening and use `catch_unwind`.
    // REVIEW: From my glance at `Module::new`, the panics occur through debug_assert, so they shouldn't occur in
    //         release mode. It might be a good idea to use `#[cfg(debug_assertions)]` to have two different versions of
    //         this code so that catch_unwind doesn't have to be used in release mode. But I do think it would be safer
    //         to just use catch_unwind regardless in case the code ever changes in the future to panic in release mode.
    let module_unwind_result = catch_unwind(move || {
        // SAFETY: LLVMModuleRef is coming directly from LLVM, and should be a valid pointer.
        ManuallyDrop::new(unsafe { Module::new(module) })
    });
    let mut module = match module_unwind_result {
        Ok(module) => module,
        Err(payload) => {
            callback.state = IRModuleOpState::Panic(payload);
            // We aren't using LLVMError, it's not necessary, and only complicates the API.
            // [https://llvm.org/doxygen/ThreadSafeModule_8h_source.html#l00113]
            // [https://llvm.org/doxygen/OrcV2CBindings_8cpp_source.html#l00744]
            return ptr::null_mut();
        },
    };
    // If `generic_ir_module_operation` is used correctly, this match should never fail. The [IRModuleOperation] `state`
    // is expected to be assigned [IRModuleOpState::Func] when initialized, and this is the first place where the value
    // is mutated.
    if let IRModuleOpState::Func(func) = callback.state.take() {
        let unwind_result = catch_unwind(move || {
            func(&mut module)
        });
        callback.state = match unwind_result {
            Ok(ret) => IRModuleOpState::Return(ret),
            Err(payload) => IRModuleOpState::Panic(payload),
        };
    } else {
        // This is how `with_module_do` (or whatever function that uses this) is notified of this specific failure.
        callback.state = IRModuleOpState::MissingFunc;
    }
    // We aren't using LLVMError, it's not necessary, and only complicates the API.
    // [https://llvm.org/doxygen/ThreadSafeModule_8h_source.html#l00113]
    // [https://llvm.org/doxygen/OrcV2CBindings_8cpp_source.html#l00744]
    ptr::null_mut()
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
        let mut op = IRModuleOperation {
            state: IRModuleOpState::Func(f),
        };
        // This result should always be null. According to the LLVM source code, it wouldn't make sense for it to be
        // non-null, as the error is user provided, and we aren't providing an error value
        // (`generic_ir_module_operation` returns null_mut).
        let result = unsafe {
            LLVMOrcThreadSafeModuleWithModuleDo(
                self.as_ptr(),
                generic_ir_module_operation::<F, R>,
                // I know this looks weird, but the second cast is necessary.
                &mut op as *mut _ as *mut _,
            )
        };
        debug_assert!(
            result.is_null(),
            "LLVMError was not null, which is unexpected.\nFile: {}:{}", file!(), line!(),
        );
        match op.state {
            // The below panic states are anticipated to never occur, but exist as a means of assurance.
            IRModuleOpState::Taken => {
                // At the moment of writing this, I am pretty sure there is no path for this error to occur.
                panic!("IRModuleOpState value was taken, but not replaced.");
            },
            IRModuleOpState::Func(_) => {
                // If this error occurs, I'm really not entirely sure what happened. Probably someone changed the
                // code in `generic_ir_module_operation`.
                panic!("IRModuleOpState function was never taken.");
            },
            IRModuleOpState::MissingFunc => {
                // If this error occurs, it likely means that the `state` field of `IRModuleOperation` was never
                // assigned to `IRModuleState::Func`, which happens near the beginning of this function.
                panic!("The IRModuleOpState value was expected to be the Func variant, but was something else.");
            }
            // Panic caught by catch_unwind.
            // REVIEW: Should this maybe be an Err, and this function return a Result?
            //         Or perhaps it makes more sense to resume the panic.
            IRModuleOpState::Panic(payload) => resume_unwind(payload),
            IRModuleOpState::Return(ret) => ret,
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
