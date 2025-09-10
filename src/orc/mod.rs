mod error;
pub mod mangled_symbol;
pub mod orc_jit_fn;
pub mod orc_module;
pub mod symbol_resolver;
pub mod symbol_table;

pub use error::OrcError;
use symbol_resolver::*;
use orc_module::OrcModule;

use std::{
    cell::RefCell, collections::HashMap, ffi::CStr, mem::MaybeUninit, pin::Pin, rc::Rc
};

use llvm_sys::{
    error::{
        LLVMDisposeErrorMessage,
        LLVMGetErrorMessage,
    },
    orc::{
        LLVMOrcAddEagerlyCompiledIR,
        LLVMOrcCreateInstance,
        LLVMOrcDisposeInstance,
        LLVMOrcJITStackRef,
        LLVMOrcModuleHandle,
    }
};

use crate::{
    module::Module, orc::{mangled_symbol::{mangle_symbol, MangledSymbol}, symbol_table::GlobalSymbolTable}, support::LLVMString, targets::TargetMachine
};

#[derive(Debug)]
struct OrcEngineInner {
    jit_stack: LLVMOrcJITStackRef,
    // inside pinned Rc so that the hashmap can be used as context in symbol resolver.
    symbol_table: GlobalSymbolTable<'static>,
}

#[derive(Debug, Clone)]
pub(crate) struct OrcEngineRc {
    inner: Rc<OrcEngineInner>,
}

impl OrcEngineRc {
    pub(crate) unsafe fn new(jit_stack: LLVMOrcJITStackRef, symbol_table: Option<&HashMap<String, u64>>) -> Self {
        Self {
            inner: Rc::new(OrcEngineInner {
                jit_stack,
                symbol_table: std::mem::transmute(GlobalSymbolTable::new(jit_stack, symbol_table)),
            })
        }
    }
    
    // TODOC (ErisianArchitect): OrcEngineRc dispose
    unsafe fn dispose(&self) -> Result<(), ()> {
        if self.inner.jit_stack.is_null() {
            return Ok(());
        }
        let err = unsafe { LLVMOrcDisposeInstance(self.inner.jit_stack) };
        if !err.is_null() {
            let cstr = unsafe { LLVMGetErrorMessage(err) };
            let scstr = unsafe { CStr::from_ptr(cstr) };
            eprintln!("Error disposing LLVMOrcJitStack: {:?}", scstr);
            unsafe { LLVMDisposeErrorMessage(cstr); }
            return Err(());
        }
        Ok(())
    }
}

impl Drop for OrcEngineRc {
    fn drop(&mut self) {
        // Check if the Rc is the last instance.
        // TODO: Come back to this if you decide to make weak references as well.
        if Rc::strong_count(&self.inner) == 1 {
            match unsafe { self.dispose() } {
                Ok(()) => (),
                Err(()) => panic!("Failed to dispose of LLVMOrcJitStack."),
            }
        }
    }
}

// TODOC (ErisianArchitect): struct OrcEngine
#[derive(Clone)]
pub struct OrcEngine {
    rc: OrcEngineRc,
}

// TODOC (ErisianArchitect): impl OrcEngine
impl OrcEngine {
    pub fn new(target_machine: &TargetMachine, symbol_table: Option<&HashMap<String, u64>>) -> Result<Self, OrcError> {
        let jit_stack = unsafe { LLVMOrcCreateInstance(target_machine.as_mut_ptr()) };
        if jit_stack.is_null() {
            return Err(OrcError::CreateInstanceFailure);
        }
        Ok(Self {
            rc: unsafe { OrcEngineRc::new(jit_stack, symbol_table) },
        })
    }
    
    pub fn symbol_table<'ctx>(&self) -> &GlobalSymbolTable<'ctx> {
        // The symbol table is 'static lifetime, sets the lifetime to the lifetime of the OrcEngine.
        unsafe { std::mem::transmute(&self.rc.inner.symbol_table) }
    }
    
    pub fn mangle_symbol(&self, name: &str) -> MangledSymbol {
        unsafe { mangle_symbol(self.rc.inner.jit_stack, name) }
    }
    
    pub fn contains_symbol(&self, name: &str) -> bool {
        self.rc.inner.symbol_table.contains_symbol(name)
    }
    
    pub fn insert_symbol_addr(&self, name: &str, addr: u64) -> Option<u64> {
        self.rc.inner.symbol_table.insert(name, addr)
    }
    
    pub fn remove_symbol(&self, name: &str) -> Option<u64> {
        self.rc.inner.symbol_table.remove(name)
    }

    // TODOC (ErisianArchitect): OrcEngine::add_eagerly_compiled_ir (improve)
    /// Add a module to the [OrcEngine], which will be eagerly compiled. You can provide
    /// a symbol_resolver to 
    /// Takes ownership of the module. It is important that you do not use the module
    /// after passing it as an argument to this function.
    pub fn add_eagerly_compiled_ir<'ctx>(
        &'ctx self,
        module: &Module<'_>,
        symbol_resolver: Option<&dyn SymbolResolver>
    ) -> Result<OrcModule<'ctx>, OrcError> {
        let module_clone = module.clone();
        let mut _sym_resolver = MaybeUninit::uninit();
        // TODO: This isn't right. _SymbolResolver cannot live on the
        //       stack.
        let resolve_fn = if let Some(resolver) = symbol_resolver {
            _sym_resolver.write(_SymbolResolver::new(resolver));
            _sym_resolver.as_mut_ptr()
        } else {
            std::ptr::null_mut()
        };
        let mut handle_result = 0 as LLVMOrcModuleHandle;
        let err = unsafe { LLVMOrcAddEagerlyCompiledIR(
            self.rc.inner.jit_stack,
            &mut handle_result,
            module_clone.as_mut_ptr(),
            if symbol_resolver.is_some() {
                Some(_symbol_resolver)
            } else {
                None
            },
            resolve_fn.cast(),
        ) };
        if !err.is_null() {
            let cstr = unsafe { LLVMGetErrorMessage(err) };
            let llvm_string = unsafe { LLVMString::new(cstr) };
            let scstr = unsafe { CStr::from_ptr(cstr) };
            eprintln!("Error adding eagerly compiled IR: {:?}", scstr);
            let llvm_string =LLVMString::create_from_c_str(scstr);
            unsafe { LLVMDisposeErrorMessage(cstr); }
            return Err(OrcError::AddEagerlyCompiledIRFailure);
        }
        Ok(unsafe { OrcModule::new(handle_result) })
    }
}