

use std::{ffi::c_void, pin::Pin, sync::{atomic::{AtomicPtr, Ordering}, Arc, Mutex}};

use llvm_sys::{error::LLVMErrorRef, orc::{LLVMOrcJITStackRef, LLVMOrcTargetAddress}};

use crate::{builder::Builder, context::Context, module::Module, orc::{
    function_address::FunctionAddress, OrcEngine, OrcEngineInner,
}};

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

// Self-referential module builder type.
#[derive(Debug)]
pub struct ModuleBuilder {
    // Pin to prevent the box from moving the memory.
    pub(crate) context: Pin<Box<Context>>,
    // 'static lifetime even though it will only live as long as the context.
    // access given externally will fix the lifetime.
    pub(crate) module: Module<'static>,
    pub(crate) builder: Builder<'static>,
}

impl ModuleBuilder {
    pub fn new(module_name: &str) -> Self {
        let context = Box::pin(Context::create());
        let module = context.create_module(module_name);
        let builder = context.create_builder();
        Self {
            module: unsafe { std::mem::transmute(module) },
            builder: unsafe { std::mem::transmute(builder) },
            context,
        }
    }
    
    #[must_use]
    #[inline]
    pub fn context(&self) -> &Context {
        &self.context
    }
    
    #[must_use]
    #[inline]
    pub fn module<'ctx>(&'ctx self) -> &'ctx Module<'ctx> {
        unsafe { std::mem::transmute(&self.module) }
    }
    
    #[must_use]
    #[inline]
    pub fn builder<'ctx>(&'ctx self) -> &'ctx Builder<'ctx> {
        unsafe { std::mem::transmute(&self.builder) }
    }
}

// pub trait LazyModuleBuilder {
//     fn build(self, engine: OrcEngine, compiler: ModuleBuilder);
// }

// pub struct LazyModuleBuilder {
    
// }

// pub struct Compiler<'ctx> {
//     context: &'ctx Context,
//     module: Module<'ctx>,
//     builder: Builder<'ctx>,
// }

#[repr(transparent)]
pub struct LazyCompileCallback {
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