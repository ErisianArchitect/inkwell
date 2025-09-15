

use std::{ffi::c_void, sync::{Mutex}};

use llvm_sys::{error::LLVMErrorRef, orc::{LLVMOrcJITStackRef, LLVMOrcTargetAddress}};

use crate::orc::{
    function_address::FunctionAddress, OrcEngine,
};

// llvm-sys has an incorrect definition for LLVMOrcLazyCompileCallbackFn, so there needs to be a correct definition for
// LLVMOrcCreateLazyCompileCallback to work.

pub type LLVMOrcLazyCompileCallbackFn
    = Option<extern "C" fn(jit_stack: LLVMOrcJITStackRef, context: *mut c_void) -> LLVMOrcTargetAddress>;

extern "C" {
    pub(crate) fn LLVMOrcCreateLazyCompileCallback(
        jit_stack: LLVMOrcJITStackRef,
        return_address: *mut LLVMOrcTargetAddress,
        callback: LLVMOrcLazyCompileCallbackFn,
        context: *mut c_void,
    ) -> LLVMErrorRef;
}

// TODOC (ErisianArchitect): trait LazyCompiler
pub trait LazyCompiler: Send + Sync + 'static {
    fn compile(self: Box<Self>, engine: OrcEngine) -> FunctionAddress;
}

impl<F: FnOnce(OrcEngine) -> FunctionAddress + Send + Sync + 'static> LazyCompiler for F {
    fn compile(self: Box<Self>, engine: OrcEngine) -> FunctionAddress {
        self(engine)
    }
}

pub struct LazyCompileCallback {
    callback: Mutex<Option<(OrcEngine, Box<dyn LazyCompiler>)>>,
}

impl LazyCompileCallback {
    #[must_use]
    #[inline]
    pub fn new<F: LazyCompiler>(engine: OrcEngine, callback: F) -> Self {
        Self {
            callback: Mutex::new(Some((engine, Box::new(callback)))),
        }
    }
    
    pub fn compile(&self) -> FunctionAddress {
        let mut callback_guard = self.callback.lock().unwrap();
        if let Some((engine, callback)) = callback_guard.take() {
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
    jit_stack: LLVMOrcJITStackRef,
    context: *const LazyCompileCallback,
) -> FunctionAddress {
    if context.is_null() {
        return FunctionAddress::null();
    }
    
    // TODO (ErisianArchitect): lazy_compile_callback implementation
    unimplemented!()
}