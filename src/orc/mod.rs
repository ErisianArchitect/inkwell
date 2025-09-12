

/*
TODO (ErisianArchitect):
[ ] Full Orc API support
[ ] Code Review
[ ] Formatting (including removing excess whitespace)
[ ] Clarification comments
[ ] Documentation
[ ] Remove this todo list when all tasks are complete.
*/

/* Notes
I'm not sure how to test crate::listeners since some of the functionality is platform dependent.
*/

mod error;
pub mod mangled_symbol;
pub mod orc_jit_fn;
pub mod orc_module;
pub mod symbol_table;

pub use error::OrcError;
use orc_module::OrcModule;

use std::{
    cell::Cell, collections::HashMap, path::Path, rc::Rc
};

use llvm_sys::orc::{
        LLVMOrcAddEagerlyCompiledIR, LLVMOrcAddLazilyCompiledIR, LLVMOrcAddObjectFile, LLVMOrcCreateInstance, LLVMOrcDisposeInstance, LLVMOrcGetSymbolAddress, LLVMOrcJITStackRef, LLVMOrcModuleHandle, LLVMOrcRegisterJITEventListener, LLVMOrcUnregisterJITEventListener
    };

use crate::{
    error::LLVMErrorString, memory_buffer::MemoryBuffer, module::Module, orc::{mangled_symbol::{mangle_symbol, MangledSymbol}, orc_jit_fn::{OrcJitFunction, UnsafeOrcJitFnPtr}, symbol_table::{module_symbol_resolver, GlobalSymbolTable, LocalSymbolTable}}, targets::TargetMachine
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct OrcEngineFlags(Cell<u16>);

impl OrcEngineFlags {
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self(Cell::new(0))
    }
    
    #[must_use]
    #[inline]
    pub(crate) fn get_flag(&self, flag: u16) -> bool {
        self.0.get() & flag == flag
    }
    
    /// Sets the flag and returns `true` if the value was changed.
    #[inline]
    fn set_flag(&self, flag: u16, on: bool) -> bool {
        if on {
            self.add_flag(flag)
        } else {
            self.remove_flag(flag)
        }
    }
    
    #[inline]
    fn add_flag(&self, flag: u16) -> bool {
        let flags = self.0.get();
        if flags & flag == flag {
            return false;
        }
        self.0.set(flags | flag);
        true
    }
    
    #[inline]
    fn remove_flag(&self, flag: u16) -> bool {
        let flags = self.0.get();
        if flags & flag == 0 {
            return false;
        }
        self.0.set(flags & !flag);
        true
    }
}

macro_rules! orc_engine_flags_impl {
    (
        $(#[$attr:meta])*
        $flag_const_name:ident = $flag_value:expr, $set_name:ident
    ) => {
        impl OrcEngineFlags {
            $(#[$attr])*
            pub(crate) const $flag_const_name: u16 = $flag_value;
            
            $(#[$attr])*
            #[inline]
            pub(crate) fn $set_name(&self, on: bool) -> bool {
                self.set_flag(Self::$flag_const_name, on)
            }
        }
    };
    ($(
        $(#[$attr:meta])*
        $flag_const_name:ident = $flag_value:expr, $set_name:ident;
    )+) => {
        $(
            orc_engine_flags_impl!{ $(#[$attr])* $flag_const_name = $flag_value, $set_name}
        )*
    };
}

orc_engine_flags_impl!(
    #[cfg(any( target_os = "linux", unix))]
    GDB_LISTENER_REGISTERED         = 1 << 0, set_gdb;
    // TODO (ErisianArchitect): Add vtune feature flag, and conditionally compile for vtune.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    INTEL_LISTENER_REGISTERED       = 1 << 1, set_intel;
    #[cfg(target_os = "linux")]
    OPROFILE_LISTENER_REGISTERED    = 1 << 2, set_oprofile;
    #[cfg(target_os = "linux")]
    PERF_LISTENER_REGISTERED        = 1 << 3, set_perf;
);

impl std::hash::Hash for OrcEngineFlags {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.get().hash(state);
    }
}

#[derive(Debug)]
pub(crate) struct OrcEngineInner {
    jit_stack: LLVMOrcJITStackRef,
    symbol_table: GlobalSymbolTable<'static>,
    /// 0: GDB_LISTENER registered
    /// 1: Intel Listener registered
    /// 2: OProfile Listener registered
    /// 3: Perf Listener registered
    flags: OrcEngineFlags,
}

impl OrcEngineInner {
    // TODOC (ErisianArchitect): OrcEngineRc dispose
    unsafe fn dispose(&self) -> Result<(), LLVMErrorString> {
        if self.jit_stack.is_null() {
            return Ok(());
        }
        let err = LLVMOrcDisposeInstance(self.jit_stack);
        if !err.is_null() {
            return Err(LLVMErrorString::from_opaque(err));
        }
        Ok(())
    }
}

impl Drop for OrcEngineInner {
    fn drop(&mut self) {
        match unsafe { self.dispose() } {
            Ok(()) => (),
            Err(err) => panic!("Failed to dispose of LLVMOrcJitStack: {err}"),
        }
    }
}

// TODO (ErisianArchitect): Better Debug implementation.
// TODOC (ErisianArchitect): struct OrcEngine
#[derive(Debug, Clone)]
pub struct OrcEngine {
    inner: Rc<OrcEngineInner>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompilationMode {
    Eager,
    Lazy,
}

// TODOC (ErisianArchitect): impl OrcEngine
impl OrcEngine {
    pub fn new(target_machine: &TargetMachine, symbol_table: Option<&HashMap<String, u64>>) -> Result<Self, OrcError> {
        let jit_stack = unsafe { LLVMOrcCreateInstance(target_machine.as_mut_ptr()) };
        if jit_stack.is_null() {
            return Err(OrcError::CreateInstanceFailure);
        }
        Ok(Self {
            inner: Rc::new(OrcEngineInner {
                jit_stack,
                symbol_table: unsafe { std::mem::transmute(GlobalSymbolTable::new(jit_stack, symbol_table)) },
                flags: OrcEngineFlags::new(),
            })
        })
    }
    
    pub(crate) fn fallback_symbol_table<'ctx>(&'ctx self) -> &'ctx GlobalSymbolTable<'ctx> {
        // SAFETY: The symbol table is 'static lifetime, sets the lifetime to the lifetime of the OrcEngine.
        unsafe { std::mem::transmute(&self.inner.symbol_table) }
    }
    
    /// Mangles name so that it can be used directly for lookups or insertions inside of this [OrcEngine].
    pub fn mangle_symbol(&self, name: &str) -> MangledSymbol {
        unsafe { mangle_symbol(self.inner.jit_stack, name) }
    }
    
    pub fn contains_mangled_symbol(&self, mangled_symbol: &MangledSymbol) -> bool {
        self.inner.symbol_table.contains_mangled(mangled_symbol)
    }
    
    pub fn contains_symbol(&self, name: &str) -> bool {
        let mangled_symbol = self.mangle_symbol(name);
        self.inner.symbol_table.contains_mangled(&mangled_symbol)
    }
    
    pub fn insert_mangled_symbol(&self, mangled_symbol: MangledSymbol, addr: u64) -> Option<u64> {
        self.inner.symbol_table.insert_mangled(mangled_symbol, addr)
    }
    
    pub fn insert_symbol(&self, name: &str, addr: u64) -> Option<u64> {
        let mangled_symbol = self.mangle_symbol(name);
        self.inner.symbol_table.insert_mangled(mangled_symbol, addr)
    }
    
    pub fn get_mangled_symbol_address(&self, mangled_symbol: &MangledSymbol) -> Result<usize, OrcError> {
        let mut symbol_result = 0u64;
        let err = unsafe {
            LLVMOrcGetSymbolAddress(self.inner.jit_stack, &mut symbol_result, mangled_symbol.to_cstr().as_ptr())
        };
        if !err.is_null() {
            return Err(OrcError::SymbolAddressLookupFailure(unsafe { LLVMErrorString::from_opaque(err) }));
        }
        Ok(symbol_result as usize)
    }
    
    pub fn get_symbol_address(&self, name: &str) -> Result<usize, OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.get_mangled_symbol_address(&mangled_symbol)
    }
    
    pub fn get_mangled_function<'ctx, F: UnsafeOrcJitFnPtr>(
        &'ctx self,
        mangled_symbol: &MangledSymbol
    ) -> Result<OrcJitFunction<'ctx, F>, OrcError> {
        let addr = self.get_mangled_symbol_address(mangled_symbol)?;
        Ok(OrcJitFunction::new(unsafe { std::mem::transmute_copy(&addr) }))
    }
    
    pub fn get_function<'ctx, F: UnsafeOrcJitFnPtr>(&'ctx self, name: &str) -> Result<OrcJitFunction<'ctx, F>, OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.get_mangled_function(&mangled_symbol)
    }
    
    /// Adds a module to the Orc JIT engine. The module is considered finalized, and cannot be modified after being
    /// added to the engine.
    /// Use [CompilationMode::Eager] to eagerly compile the module (compilation is immediate).
    /// Use [CompilationMode::Lazy] to lazily compile the module (compilation on demand).
    /// 
    /// The `local_symbol_table` is expected to be a table of function names mapped to addresses to `extern "C"`
    /// functions.
    /// # Example
    /// ```rust, no_run
    /// let module = ...;
    /// let target_data = ...;
    /// 
    /// let engine = OrcEngine::new(&target_data, None);
    /// 
    /// extern "C" fn extern_fn() {
    ///     println!("extern_fn()");
    /// }
    /// 
    /// let map = HashMap::from([
    ///     (String::from("extern_fn"), extern_fn as u64),
    /// ]);
    /// 
    /// let orc_module = match engine.add_module(module, CompilationMode::Eager, Some(&map)) {
    ///     Ok(module) => module,
    ///     Err(err) => eprintln!("OrcError: {err:?}"),
    /// };
    /// ```
    pub fn add_module<'ctx>(
        &'ctx self,
        module: Module<'_>,
        compilation_mode: CompilationMode,
        local_symbol_table: Option<&HashMap<String, u64>>,
    ) -> Result<OrcModule<'ctx>, OrcError> {
        // LLVMOrcAddCompiledIR takes ownership of the module, so it must be prevented from being dropped and
        // disposed. if module is owned by execution engine, that is considered an error.
        // https://groups.google.com/g/llvm-dev/c/JAFXZKuixyE?pli=1
        if module.owned_by_ee.borrow().is_some() {
            return Err(OrcError::ModuleOwnedByExecutionEngine);
        }
        let module = std::mem::ManuallyDrop::new(module);
        // Be free, data_layout!
        module.data_layout.borrow_mut().take();
        let local_table = LocalSymbolTable::new(self.inner.symbol_table.clone(), local_symbol_table);
        let add_compiled_ir_fn = match compilation_mode {
            CompilationMode::Eager => LLVMOrcAddEagerlyCompiledIR,
            CompilationMode::Lazy => LLVMOrcAddLazilyCompiledIR,
        };
        let mut handle_result = 0 as LLVMOrcModuleHandle;
        let err = unsafe { add_compiled_ir_fn(
            self.inner.jit_stack,
            &mut handle_result,
            module.as_mut_ptr(),
            Some(module_symbol_resolver),
            // This gets a pointer to the LocalSymbolTableInner within the Rc in the LocalSymbolTable.
            // this is used as the context for the module_symbol_resolver.
            local_table.as_ptr().cast(),
        ) };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::from_opaque(err) };
            return Err(match compilation_mode {
                CompilationMode::Eager => OrcError::AddEagerlyCompiledIRFailure(err_string),
                CompilationMode::Lazy => OrcError::AddLazilyCompiledIRFailure(err_string),
            });
        }
        Ok(unsafe { OrcModule::new(self.inner.clone(), handle_result, local_table) })
    }
    
    pub fn add_object_from_memory<'ctx>(
        &self,
        memory_buffer: &MemoryBuffer,
        local_symbol_table: Option<&HashMap<String, u64>>,
    ) -> Result<OrcModule<'ctx>, OrcError> {
        let local_table = LocalSymbolTable::new(self.inner.symbol_table.clone(), local_symbol_table);
        let mut handle = 0u64;
        let err = unsafe { LLVMOrcAddObjectFile(
            self.inner.jit_stack,
            &mut handle,
            memory_buffer.as_mut_ptr(),
            Some(module_symbol_resolver),
            local_table.as_ptr().cast(),
        ) };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::from_opaque(err) };
            return Err(OrcError::AddObjectFileFailure(err_string))
        }
        Ok(unsafe { OrcModule::new(self.inner.clone(), handle, local_table) })
    }
    
    pub fn add_object_file<'ctx, P: AsRef<Path>>(
        &self,
        object_file_path: P,
        local_symbol_table: Option<&HashMap<String, u64>>,
    ) -> Result<OrcModule<'ctx>, OrcError> {
        let mem_buff = MemoryBuffer::create_from_file(object_file_path.as_ref())?;
        self.add_object_from_memory(&mem_buff, local_symbol_table)
    }
    
    #[cfg(any(target_os = "linux", unix))]
    pub fn add_gdb_registration_listener(&self) {
        if !self.inner.flags.set_gdb(true) {
            return;
        }
        let event_listener = crate::listener::JitEventListener::gdb();
        unsafe { LLVMOrcRegisterJITEventListener(self.inner.jit_stack, event_listener.raw); }
    }
    
    #[cfg(any(target_os = "linux", unix))]
    pub fn remove_gdb_registration_listener(&self) {
        if !self.inner.flags.set_gdb(false) {
            return;
        }
        let event_listener = crate::listener::JitEventListener::gdb();
        unsafe { LLVMOrcUnregisterJITEventListener(self.inner.jit_stack, event_listener.raw); }
    }
    
    // TODO (ErisianArchitect): Add vtune feature flag, and conditionally compile for vtune.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn add_intel_event_listener(&self) {
        if !self.inner.flags.set_intel(true) {
            return;
        }
        let event_listener = crate::listener::JitEventListener::intel();
        unsafe { LLVMOrcRegisterJITEventListener(self.inner.jit_stack, event_listener.raw); }
    }
    
    // TODO (ErisianArchitect): Add vtune feature flag, and conditionally compile for vtune.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn remove_intel_event_listener(&self) {
        if !self.inner.flags.set_intel(false) {
            return;
        }
        let event_listener = crate::listener::JitEventListener::intel();
        unsafe { LLVMOrcUnregisterJITEventListener(self.inner.jit_stack, event_listener.raw); }
    }
    
    #[cfg(target_os = "linux")]
    pub fn add_oprofile_event_listener(&self) {
        if !self.inner.flags.set_oprofile(true) {
            return;
        }
        let event_listener = crate::listener::JitEventListener::oprofile();
        unsafe { LLVMOrcRegisterJITEventListener(self.inner.jit_stack, event_listener.raw); }
    }
    
    #[cfg(target_os = "linux")]
    pub fn remove_oprofile_event_listener(&self) {
        if !self.inner.flags.set_oprofile(false) {
            return;
        }
        let event_listener = crate::listener::JitEventListener::oprofile();
        unsafe { LLVMOrcUnregisterJITEventListener(self.inner.jit_stack, event_listener.raw); }
    }
    
    #[cfg(target_os = "linux")]
    pub fn add_perf_event_listener(&self) {
        if !self.inner.flags.set_perf(true) {
            return;
        }
        let event_listener = crate::listener::JitEventListener::perf();
        unsafe { LLVMOrcRegisterJITEventListener(self.inner.jit_stack, event_listener.raw); }
    }
    
    #[cfg(target_os = "linux")]
    pub fn remove_perf_event_listner(&self) {
        if !self.inner.flags.set_perf(false) {
            return;
        }
        let event_listener = crate::listener::JitEventListener::perf();
        unsafe { LLVMOrcUnregisterJITEventListener(self.inner.jit_stack, event_listener.raw); }
    }
}