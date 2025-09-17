

use std::{ffi::c_void, sync::{atomic::{AtomicPtr, Ordering}, Arc, Mutex}};

use llvm_sys::{error::LLVMErrorRef, orc::{LLVMOrcJITStackRef, LLVMOrcTargetAddress}};

use crate::orc::{
    function_address::FunctionAddress, OrcEngine, OrcEngineInner,
};

// llvm-sys has an incorrect definition for LLVMOrcLazyCompileCallbackFn, so there needs to be a correct definition for
// LLVMOrcCreateLazyCompileCallback to work.

pub(crate) type WeakOrcEngine = std::sync::Weak<OrcEngineInner>;

pub(crate) type LLVMOrcLazyCompileCallbackFn
    = Option<extern "C" fn(jit_stack: LLVMOrcJITStackRef, context: *const LazyCompileCallback) -> FunctionAddress>;

extern "C" {
    pub(crate) fn LLVMOrcCreateLazyCompileCallback(
        jit_stack: LLVMOrcJITStackRef,
        return_address: *mut LLVMOrcTargetAddress,
        callback: LLVMOrcLazyCompileCallbackFn,
        context: *const LazyCompileCallback,
    ) -> LLVMErrorRef;
}

// TODOC (ErisianArchitect): trait LazyCompiler
pub trait LazyCompiler: Send + Sync + 'static {
    // Should return FunctionAddress::NULL if compilation fails.
    fn compile(self: Box<Self>, engine: OrcEngine) -> FunctionAddress;
}

impl<F: FnOnce(OrcEngine) -> FunctionAddress + Send + Sync + 'static> LazyCompiler for F {
    fn compile(self: Box<Self>, engine: OrcEngine) -> FunctionAddress {
        self(engine)
    }
}

pub struct LazyCompileCallback {
    // The idea is that the LazyCompiler will only be used a single time, but may not be used at all.
    // So the LazyCompileCallback lives inside of the OrcEngine that it is registered to, and also carries its own
    // weak reference to the OrcEngineInner. This prevents a cycle that would cause a leak.
    // When the compile function is called, the weak reference is upgraded. If the upgrade fails, the compile function
    // will return FunctionAddress::NULL.
    callback: Mutex<Option<(WeakOrcEngine, Box<dyn LazyCompiler>)>>,
}

impl LazyCompileCallback {
    #[must_use]
    #[inline]
    pub fn new<F: LazyCompiler>(engine: &OrcEngine, callback: F) -> Self {
        Self {
            callback: Mutex::new(Some((Arc::downgrade(&engine.inner), Box::new(callback)))),
        }
    }
    
    fn compile(&self) -> FunctionAddress {
        let mut callback_guard = self.callback.lock().unwrap();
        if let Some((weak_engine, callback)) = callback_guard.take() {
            let Some(strong_engine) = weak_engine.upgrade() else {
                return FunctionAddress::NULL;
            };
            let engine = OrcEngine {
                inner: strong_engine
            };
            callback.compile(engine)
        } else {
            FunctionAddress::NULL
        }
    }
}

impl std::fmt::Debug for LazyCompileCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LazyCompileCallback")
    }
}

// TODOC (ErisianArchitect): fn lazy_compile_callback
pub(crate) extern "C" fn lazy_compile_callback(
    // This is unused because we need access to the OrcEngine, which lives inside the LazyCompileCallback. Consider
    // using a mutable static to store a hashmap of <LLVMOrcJITStackRef, std::sync::Weak<OrcEngine>> to reduce the
    // memory footprint of the LazyCompileCallback.
    jit_stack: LLVMOrcJITStackRef,
    context: *const LazyCompileCallback,
) -> FunctionAddress {
    let context_ref = unsafe { context.as_ref() };
    let Some(context) = context_ref else {
        return FunctionAddress::NULL;
    };
    context.compile()
}