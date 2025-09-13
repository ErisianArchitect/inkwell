
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

pub mod compile_callback;
pub mod error;
pub mod mangled_symbol;
pub mod orc_jit_fn;
// pub mod orc_module;
pub mod symbol_table;

pub use error::OrcError;
// use orc_module::OrcModule;

use std::{
    cell::{Cell, RefCell}, collections::HashMap, mem::transmute_copy, path::Path, rc::Rc
};

use llvm_sys::orc::{
    LLVMOrcAddEagerlyCompiledIR,
    LLVMOrcAddLazilyCompiledIR,
    LLVMOrcAddObjectFile,
    LLVMOrcCreateIndirectStub,
    LLVMOrcCreateInstance,
    LLVMOrcDisposeInstance,
    LLVMOrcGetSymbolAddress,
    LLVMOrcGetSymbolAddressIn,
    LLVMOrcRegisterJITEventListener,
    LLVMOrcRemoveModule,
    LLVMOrcSetIndirectStubPointer,
    LLVMOrcUnregisterJITEventListener,
    LLVMOrcJITStackRef,
    LLVMOrcModuleHandle,
    LLVMOrcTargetAddress,
};

use crate::{
    error::LLVMErrorString,
    memory_buffer::MemoryBuffer,
    module::Module,
    orc::{
        mangled_symbol::{
            mangle_symbol,
            MangledSymbol
        },
        orc_jit_fn::{
            OrcFunction,
            UnsafeOrcFn
        },
        symbol_table::{
            module_symbol_resolver,
            GlobalSymbolTable,
            LocalSymbolTable, SymbolTable
        }
    },
    targets::TargetMachine,
};

// TODOC (ErisianArchitect): struct TargetAddress
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TargetAddress {
    pub(crate) address: LLVMOrcTargetAddress
}

// TODOC (ErisianArchitect): impl TargetAddress
impl TargetAddress {
    #[must_use]
    #[inline]
    pub fn new<F: UnsafeOrcFn>(function: F) -> Self {
        let address: usize = unsafe { transmute_copy(&function) };
        unsafe { Self::new_raw(address as LLVMOrcTargetAddress) }
    }
    
    /// Unsafe fallback for functions that cannot be represented with `UnsafeOrcJitFnPtr`.
    #[must_use]
    #[inline]
    pub unsafe fn new_raw(address: LLVMOrcTargetAddress) -> Self {
        Self {
            address
        }
    }
    
    #[must_use]
    #[inline]
    pub fn get_address(self) -> LLVMOrcTargetAddress {
        self.address
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompilationMode {
    // Eager compilation is broken for Windows, I believe, so perhaps this should be removed on Windows?
    // https://stackoverflow.com/questions/49866755/rust-llvm-orc-jit-cannot-find-symbol-address
    /// Compile immediately.
    /// # Warning!
    /// ***This does not work on Windows.***
    Eager,
    /// Compile on demand. Functions will not be compiled until their first resolution.
    Lazy,
}

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

macro_rules! orc_engine_event_listener_flags_impl {
    (
        $(#[$attr:meta])*
        $flag_const_name:ident = $flag_value:expr,
        $set_name:ident,
        $has_name:ident,
        $listener_name:ident,
        $add_listener_name:ident,
        $remove_listener_name:ident,
        $has_listener_name:ident
    ) => {
        impl OrcEngineFlags {
            $(#[$attr])*
            pub(crate) const $flag_const_name: u16 = $flag_value;
            
            $(#[$attr])*
            #[inline]
            pub(crate) fn $set_name(&self, on: bool) -> bool {
                self.set_flag(Self::$flag_const_name, on)
            }
            
            $(#[$attr])*
            #[inline]
            pub(crate) fn $has_name(&self) -> bool {
                self.get_flag(Self::$flag_const_name)
            }
        }
        
        impl OrcEngine {
            $(#[$attr])*
            pub fn $add_listener_name(&self) {
                if !self.inner.flags.$set_name(true) {
                    return;
                }
                let event_listener = crate::listener::JitEventListener::$listener_name();
                unsafe { LLVMOrcRegisterJITEventListener(self.inner.jit_stack, event_listener.raw) };
            }
            
            $(#[$attr])*
            pub fn $remove_listener_name(&self) {
                if !self.inner.flags.$set_name(false) {
                    return;
                }
                let event_listener = crate::listener::JitEventListener::$listener_name();
                unsafe { LLVMOrcUnregisterJITEventListener(self.inner.jit_stack, event_listener.raw) };
            }
            
            $(#[$attr])*
            pub fn $has_listener_name(&self) -> bool {
                self.inner.flags.$has_name()
            }
        }
    };
    ($(
        $(#[$attr:meta])*
        $flag_const_name:ident = $flag_value:expr,
        $set_name:ident, $has_name:ident,
        $listener_name:ident,
        $add_listener_name:ident,
        $remove_listener_name:ident,
        $has_listener_name:ident;
    )+) => {
        $(
            orc_engine_event_listener_flags_impl!{
                $(#[$attr])*
                $flag_const_name = $flag_value,
                $set_name,
                $has_name,
                $listener_name,
                $add_listener_name,
                $remove_listener_name,
                $has_listener_name
            }
        )*
    };
}

orc_engine_event_listener_flags_impl!(
    #[cfg(any(target_os = "linux", unix))]
    GDB_LISTENER_REGISTERED         = 1 << 0,
    set_gdb,
    has_gdb,
    gdb,
    add_gdb_registration_listener,
    remove_gdb_registration_listener,
    has_gdb_registration_listener;
    
    // TODO (ErisianArchitect): Add vtune feature flag, and conditionally compile for vtune.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    INTEL_LISTENER_REGISTERED       = 1 << 1,
    set_intel,
    has_intel,
    intel,
    add_intel_event_listener,
    remove_intel_event_listener,
    has_intel_event_listener;
    
    #[cfg(target_os = "linux")]
    OPROFILE_LISTENER_REGISTERED    = 1 << 2,
    set_oprofile,
    has_oprofile,
    oprofile,
    add_oprofile_event_listener,
    remove_oprofile_event_listener,
    has_oprofile_event_listener;
    
    #[cfg(target_os = "linux")]
    PERF_LISTENER_REGISTERED        = 1 << 3,
    set_perf,
    has_perf,
    perf,
    add_perf_event_listener,
    remove_perf_event_listner,
    has_perf_event_listener;
);

impl std::hash::Hash for OrcEngineFlags {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.get().hash(state);
    }
}

#[derive(Debug)]
pub(crate) struct OrcModule {
    pub(crate) handle: LLVMOrcModuleHandle,
    // This just needs to live as long as the OrcModule exists.
    /// Used for per-module symbol resolution with global symbol table fallback.
    pub(crate) _symbol_table: LocalSymbolTable<'static>,
}

impl OrcModule {
    pub(crate) fn new(handle: LLVMOrcModuleHandle, symbol_table: LocalSymbolTable<'_>) -> Self {
        Self {
            handle,
            _symbol_table: unsafe { std::mem::transmute(symbol_table) },
        }
    }
}

#[derive(Debug)]
pub(crate) struct OrcEngineInner {
    pub(crate) jit_stack: LLVMOrcJITStackRef,
    pub(crate) symbol_table: GlobalSymbolTable<'static>,
    pub(crate) modules: RefCell<HashMap<Box<str>, OrcModule>>,
    /// 0: GDB_LISTENER registered
    /// 1: Intel Listener registered
    /// 2: OProfile Listener registered
    /// 3: Perf Listener registered
    pub(crate) flags: OrcEngineFlags,
}

impl Drop for OrcEngineInner {
    fn drop(&mut self) {
        debug_assert!(!self.jit_stack.is_null(), "jit_stack was null on drop.");
        let err = unsafe { LLVMOrcDisposeInstance(self.jit_stack) };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            panic!("LLVM Error on OrcEngine drop: {err_string}");
        }
    }
}

// TODO (ErisianArchitect): Better Debug implementation.
// TODOC (ErisianArchitect): struct OrcEngine
#[derive(Debug, Clone)]
pub struct OrcEngine {
    inner: Rc<OrcEngineInner>,
}

// TODOC (ErisianArchitect): impl OrcEngine
impl OrcEngine {
    #[must_use]
    pub fn new(target_machine: &TargetMachine) -> Result<Self, OrcError> {
        let jit_stack = unsafe { LLVMOrcCreateInstance(target_machine.as_mut_ptr()) };
        if jit_stack.is_null() {
            return Err(OrcError::CreateInstanceFailure);
        }
        Ok(Self {
            inner: Rc::new(OrcEngineInner {
                jit_stack,
                symbol_table: unsafe { std::mem::transmute(GlobalSymbolTable::new(jit_stack, None)) },
                modules: RefCell::new(HashMap::new()),
                flags: OrcEngineFlags::new(),
            })
        })
    }
    
    #[must_use]
    #[inline]
    pub fn jit_stack_ref(&self) -> LLVMOrcJITStackRef {
        self.inner.jit_stack
    }
    
    // Unfortunately there is no demangle function, so this is an irreversible operation.
    // There should be a way to demangle it, but that would be up to the user of the api.
    /// Mangles name so that it can be used directly for lookups or insertions inside of this [OrcEngine].
    #[must_use]
    pub fn mangle_symbol(&self, name: &str) -> MangledSymbol {
        unsafe { mangle_symbol(self.inner.jit_stack, name) }
    }
    
    #[must_use]
    pub fn create_symbol_table<'ctx>(&'ctx self) -> SymbolTable<'ctx> {
        SymbolTable::new(self.inner.jit_stack)
    }
    
    #[must_use]
    pub fn contains_mangled_symbol(&self, mangled_symbol: &MangledSymbol) -> Result<bool, OrcError> {
        let mut symbol_result = 0u64;
        let err = unsafe {
            LLVMOrcGetSymbolAddress(self.inner.jit_stack, &mut symbol_result, mangled_symbol.to_cstr().as_ptr())
        };
        if !err.is_null() {
            return Err(OrcError::SymbolAddressLookupFailure(unsafe { LLVMErrorString::new(err) }));
        }
        if symbol_result == 0 {
            return Ok(false);
        }
        Ok(true)
    }
    
    #[must_use]
    pub fn contains_symbol(&self, name: &str) -> Result<bool, OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.contains_mangled_symbol(&mangled_symbol)
    }
    
    pub fn create_mangled_indirect_stub<F: UnsafeOrcFn>(&self, mangled_symbol: MangledSymbol, function: F) -> Result<(), OrcError> {
        let addr: usize = unsafe { transmute_copy(&function) };
        let err = unsafe {
            LLVMOrcCreateIndirectStub(self.inner.jit_stack, mangled_symbol.as_ptr(), addr as LLVMOrcTargetAddress)
        };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::CreateIndirectStubFailure(err_string));
        }
        Ok(())
    }
    
    pub fn create_indirect_stub<F: UnsafeOrcFn>(&self, name: &str, function: F) -> Result<(), OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.create_mangled_indirect_stub(mangled_symbol, function)
    }
    
    pub fn set_mangled_indirect_stub<F: UnsafeOrcFn>(&self, mangled_symbol: &MangledSymbol, function: F) -> Result<(), OrcError> {
        let addr: usize = unsafe { transmute_copy(&function) };
        let err = unsafe {
            LLVMOrcSetIndirectStubPointer(self.inner.jit_stack, mangled_symbol.as_ptr(), addr as LLVMOrcTargetAddress)
        };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::SetIndirectStubFailure(err_string));
        }
        Ok(())
    }
    
    pub fn set_indirect_stub<F: UnsafeOrcFn>(&self, name: &str, function: F) -> Result<(), OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.set_mangled_indirect_stub(&mangled_symbol, function)
    }
    
    #[must_use]
    pub fn register_mangled_function<F: UnsafeOrcFn>(&self, mangled_symbol: MangledSymbol, f: F) -> Result<(), OrcError> {
        let address: usize = unsafe { std::mem::transmute_copy(&f) };
        if let Some(found_addr) = self.inner.symbol_table.insert_mangled(mangled_symbol.clone(), address as u64) {
            // insert back into the table
            self.inner.symbol_table.insert_mangled(mangled_symbol.clone(), found_addr);
            return Err(OrcError::MangledFunctionAlreadyRegistered(mangled_symbol));
        }
        Ok(())
    }
    
    #[must_use]
    pub fn register_function<F: UnsafeOrcFn>(&self, name: &str, f: F) -> Result<(), OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.register_mangled_function(mangled_symbol, f)
    }
    
    #[must_use]
    pub unsafe fn get_mangled_symbol_address(&self, mangled_symbol: &MangledSymbol) -> Result<usize, OrcError> {
        let mut symbol_result = 0u64;
        let err = unsafe {
            LLVMOrcGetSymbolAddress(self.inner.jit_stack, &mut symbol_result, mangled_symbol.as_ptr())
        };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::SymbolAddressLookupFailure(err_string));
        }
        if symbol_result == 0 {
            return Err(OrcError::MangledSymbolNotFound(mangled_symbol.clone()));
        }
        Ok(symbol_result as usize)
    }
    
    #[must_use]
    pub unsafe fn get_symbol_address(&self, name: &str) -> Result<usize, OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.get_mangled_symbol_address(&mangled_symbol)
    }
    
    #[must_use]
    pub unsafe fn get_mangled_symbol_address_in(&self, module: &str, mangled_symbol: &MangledSymbol) -> Result<usize, OrcError> {
        let Some(&OrcModule { handle: module_handle, .. }) = self.inner.modules.borrow().get(module) else {
            return Err(OrcError::ModuleNotFound(module.into()));
        };
        let mut symbol_result = 0u64;
        let err = unsafe {
            LLVMOrcGetSymbolAddressIn(
                self.inner.jit_stack,
                &mut symbol_result,
                module_handle,
                mangled_symbol.to_cstr().as_ptr(),
            )
        };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::SymbolAddressLookupFailure(err_string));
        }
        if symbol_result == 0 {
            return Err(OrcError::MangledSymbolNotFound(mangled_symbol.clone()));
        }
        Ok(symbol_result as usize)
    }
    
    #[must_use]
    pub unsafe fn get_symbol_address_in(&self, module: &str, symbol: &str) -> Result<usize, OrcError> {
        let mangled_symbol = self.mangle_symbol(symbol);
        self.get_mangled_symbol_address_in(module, &mangled_symbol)
    }
    
    #[must_use]
    pub unsafe fn get_mangled_function<'ctx, F: UnsafeOrcFn>(
        &'ctx self,
        mangled_symbol: &MangledSymbol
    ) -> Result<OrcFunction<'ctx, F>, OrcError> {
        let addr = self.get_mangled_symbol_address(mangled_symbol)?;
        Ok(OrcFunction::new(unsafe { std::mem::transmute_copy(&addr) }))
    }
    
    #[must_use]
    pub unsafe fn get_function<'ctx, F: UnsafeOrcFn>(
        &'ctx self,
        name: &str,
    ) -> Result<OrcFunction<'ctx, F>, OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.get_mangled_function(&mangled_symbol)
    }
    
    #[must_use]
    pub unsafe fn get_mangled_function_in<'ctx, F: UnsafeOrcFn>(
        &'ctx self,
        module: &str,
        mangled_symbol: &MangledSymbol,
    ) -> Result<OrcFunction<'ctx, F>, OrcError> {
        let addr = self.get_mangled_symbol_address_in(module, mangled_symbol)?;
        Ok(OrcFunction::new(unsafe { std::mem::transmute_copy(&addr) }))
    }
    
    #[must_use]
    pub unsafe fn get_function_in<'ctx, F: UnsafeOrcFn>(
        &'ctx self,
        module: &str,
        symbol: &str,
    ) -> Result<OrcFunction<'ctx, F>, OrcError> {
        let mangled_symbol = self.mangle_symbol(symbol);
        self.get_mangled_function_in(module, &mangled_symbol)
    }
    
    /// Adds a module to the Orc JIT engine. The module is considered finalized, and cannot be modified after being
    /// added to the engine.
    /// Use [CompilationMode::Eager] to eagerly compile the module (compilation is immediate).
    /// Use [CompilationMode::Lazy] to lazily compile the module (compilation on demand).
    /// 
    /// The `local_symbol_table` is expected to be a table of function names mapped to addresses to `extern "C"`
    /// functions.
    /// 
    /// The module name must be unique (no other module added to this engine by that name).
    #[must_use]
    pub fn add_module<'ctx>(
        &'ctx self,
        name: &str,
        module: Module<'_>,
        compilation_mode: CompilationMode,
        local_symbol_table: Option<SymbolTable<'_>>,
    ) -> Result<(), OrcError> {
        let symbol_table = if let Some(symbol_table) = local_symbol_table {
            if symbol_table.jit_stack != self.inner.jit_stack {
                return Err(OrcError::NotOwnedByOrcEngine);
            }
            symbol_table.take_inner()
        } else {
            HashMap::new()
        };
        if self.inner.modules.borrow().contains_key(name) {
            return Err(OrcError::RepeatModuleName(name.into()));
        }
        // LLVMOrcAddCompiledIR takes ownership of the module, so it must be prevented from being dropped and
        // disposed. if module is owned by execution engine, that is considered an error.
        // https://groups.google.com/g/llvm-dev/c/JAFXZKuixyE?pli=1
        if module.owned_by_ee.borrow().is_some() {
            return Err(OrcError::ModuleOwnedByExecutionEngine);
        }
        let module = std::mem::ManuallyDrop::new(module);
        // Be free, data_layout!
        let local_table = LocalSymbolTable::new(self.inner.symbol_table.clone(), symbol_table);
        let add_compiled_ir_fn = match compilation_mode {
            CompilationMode::Eager => LLVMOrcAddEagerlyCompiledIR,
            CompilationMode::Lazy => LLVMOrcAddLazilyCompiledIR,
        };
        let mut handle = 0 as LLVMOrcModuleHandle;
        let err = unsafe { add_compiled_ir_fn(
            self.inner.jit_stack,
            &mut handle,
            module.as_mut_ptr(),
            Some(module_symbol_resolver),
            // // This gets a pointer to the LocalSymbolTableInner within the Rc in the LocalSymbolTable.
            // // this is used as the context for the module_symbol_resolver.
            local_table.as_ptr().cast(),
        ) };
        module.data_layout.borrow_mut().take();
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(match compilation_mode {
                CompilationMode::Eager => OrcError::AddEagerlyCompiledIRFailure(err_string),
                CompilationMode::Lazy => OrcError::AddLazilyCompiledIRFailure(err_string),
            });
        }
        self.inner.modules.borrow_mut().insert(name.into(), OrcModule::new(handle, local_table));
        Ok(())
    }
    
    #[must_use]
    pub fn add_object_from_memory<'ctx>(
        &self,
        name: &str,
        memory_buffer: &MemoryBuffer,
        local_symbol_table: Option<SymbolTable>,
    ) -> Result<(), OrcError> {
        let symbol_table = if let Some(symbol_table) = local_symbol_table {
            if symbol_table.jit_stack != self.inner.jit_stack {
                return Err(OrcError::NotOwnedByOrcEngine);
            }
            symbol_table.take_inner()
        } else {
            HashMap::new()
        };
        if self.inner.modules.borrow().contains_key(name) {
            return Err(OrcError::RepeatModuleName(name.into()));
        }
        let local_table = LocalSymbolTable::new(self.inner.symbol_table.clone(), symbol_table);
        let mut handle = 0u64;
        let err = unsafe { LLVMOrcAddObjectFile(
            self.inner.jit_stack,
            &mut handle,
            memory_buffer.as_mut_ptr(),
            Some(module_symbol_resolver),
            local_table.as_ptr().cast(),
        ) };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::AddObjectFileFailure(err_string))
        }
        self.inner.modules.borrow_mut().insert(name.into(), OrcModule::new(handle, local_table));
        Ok(())
    }
    
    #[must_use]
    pub fn add_object_file<'ctx, P: AsRef<Path>>(
        &self,
        name: &str,
        object_file_path: P,
        local_symbol_table: Option<SymbolTable>,
    ) -> Result<(), OrcError> {
        // this is going to be repeated in `add_object_from_memory`, but it is preferable to do this check before
        // creating the memory buffer. It won't matter that it's done a second time.
        // perhaps in the future there could be a separate method that has a flag for whether or not to check the
        // if there is already a module by that name.
        if self.inner.modules.borrow().contains_key(name) {
            return Err(OrcError::RepeatModuleName(name.into()));
        }
        let mem_buff = MemoryBuffer::create_from_file(object_file_path.as_ref())?;
        self.add_object_from_memory(name, &mem_buff, local_symbol_table)
    }
    
    #[must_use]
    pub fn remove_module(&self, name: &str) -> Result<(), OrcError> {
        if let Some(module) = self.inner.modules.borrow_mut().remove(name) {
            let err = unsafe { LLVMOrcRemoveModule(self.inner.jit_stack, module.handle) };
            if !err.is_null() {
                let err_string = unsafe { LLVMErrorString::new(err) };
                return Err(OrcError::RemoveModuleFailure(err_string));
            }
            Ok(())
        } else {
            Err(OrcError::ModuleNotFound(name.into()))
        }
    }
    
    #[inline]
    pub fn has_module(&self, name: &str) -> bool {
        self.inner.modules.borrow().contains_key(name)
    }
}