

use std::{ffi::c_void, sync::{Arc, Mutex}};

use llvm_sys::{error::LLVMErrorRef, orc::{LLVMOrcJITStackRef, LLVMOrcTargetAddress}};

use crate::orc::{
    function_address::FunctionAddress, OrcEngine, OrcEngineInner,
};

// llvm-sys has an incorrect definition for LLVMOrcLazyCompileCallbackFn, so there needs to be a correct definition for
// LLVMOrcCreateLazyCompileCallback to work.

pub(crate) type WeakOrcEngine = std::sync::Weak<OrcEngineInner>;

pub(crate) type LLVMOrcLazyCompileCallbackFn
    = Option<extern "C" fn(jit_stack: LLVMOrcJITStackRef, context: *const c_void) -> FunctionAddress>;

extern "C" {
    pub(crate) fn LLVMOrcCreateLazyCompileCallback(
        jit_stack: LLVMOrcJITStackRef,
        return_address: *mut LLVMOrcTargetAddress,
        callback: LLVMOrcLazyCompileCallbackFn,
        context: *const c_void,
    ) -> LLVMErrorRef;
}

/// A trait for lazy compilation in the [OrcEngine].
pub trait LazyCompiler: Send + Sync + 'static {
    /// Compiles the function for the given [OrcEngine]. Should return [FunctionAddress::NULL] on failure.
    fn compile(self: Box<Self>, engine: OrcEngine) -> FunctionAddress;
}

impl<F: FnOnce(OrcEngine) -> FunctionAddress + Send + Sync + 'static> LazyCompiler for F {
    #[inline(always)]
    fn compile(self: Box<Self>, engine: OrcEngine) -> FunctionAddress {
        self(engine)
    }
}

#[repr(transparent)]
pub(crate) struct LazyCompileCallback {
    // The idea is that the LazyCompiler will only be used a single time, but may not be used at all.
    // So the LazyCompileCallback lives inside of the OrcEngine that it is registered to, and also carries its own
    // weak reference to the OrcEngineInner. This prevents a cycle that would cause a leak.
    // When the compile function is called, the weak reference is upgraded. If the upgrade fails, the compile function
    // will return FunctionAddress::NULL.
    pub(crate) callback: Mutex<Option<(WeakOrcEngine, Box<dyn LazyCompiler>)>>,
}

impl LazyCompileCallback {
    #[must_use]
    #[inline]
    pub fn new<F: LazyCompiler>(engine: &OrcEngine, callback: F) -> Self {
        Self {
            callback: Mutex::new(Some((Arc::downgrade(&engine.inner), Box::new(callback)))),
        }
    }
    
    /// Performs lazy compilation, then returns the [FunctionAddress] for the compiled function.
    fn compile(&self) -> FunctionAddress {
        let mut callback_guard = self.callback.lock().unwrap();
        let Some((weak_engine, callback)) = callback_guard.take() else {
            eprintln!("Error: (LazyCompileCallback::compile) Lazy Compile Callback already used.");
            return FunctionAddress::NULL;
        };
        let Some(strong_engine) = weak_engine.upgrade() else {
            eprintln!("Error: (LazyCompileCallback::compile) Unable to upgrade `weak_engine` to strong reference.");
            return FunctionAddress::NULL;
        };
        let engine = OrcEngine {
            inner: strong_engine
        };
        callback.compile(engine)
    }
}

impl std::fmt::Debug for LazyCompileCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LazyCompileCallback")
    }
}

/// The `extern "C"` function used for lazy compilation.
pub(crate) extern "C" fn lazy_compile_callback(
    // NOTE: This is unused because we need access to the OrcEngine, which lives inside the LazyCompileCallback.
    // Consider using a mutable static to store a hashmap of <LLVMOrcJITStackRef, std::sync::Weak<OrcEngine>> to
    // reduce the memory footprint of the LazyCompileCallback.
    _jit_stack: LLVMOrcJITStackRef,
    callback_ptr: *const c_void,
) -> FunctionAddress {
    let callback_ref: Option<&LazyCompileCallback> = unsafe { callback_ptr.cast::<LazyCompileCallback>().as_ref() };
    let Some(callback) = callback_ref else {
        return FunctionAddress::NULL;
    };
    callback.compile()
}