
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
--- I'm not sure how to test crate::listeners since some of the functionality is platform dependent.
--- The entire Orc Engine is thread-safe, but the JITed code itself can continue executing even after the JITStack has
    been disposed of. This would cause undefined behavior, likely a segfault. This should be documented, and perhaps
    even give users of the API the ability to keep the engine alive and then release ownership at some point.
*/

pub mod compile_callback;
pub mod error;
pub mod mangled_symbol;
pub mod function_address;
pub mod orc_jit_fn;
pub mod symbol_table;

use std::{
    collections::HashMap, mem::transmute_copy, path::Path, sync::{Arc, RwLock, RwLockWriteGuard}
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
    LLVMOrcRemoveModule,
    LLVMOrcSetIndirectStubPointer,
    LLVMOrcJITStackRef,
    LLVMOrcModuleHandle,
    LLVMOrcTargetAddress,
};

// TODO: Update this cfg if any listeners are added that have different requirements.
#[cfg(any(
    any(target_os = "linux", unix),
    all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
))]
use {
    std::sync::atomic::AtomicU16,
    llvm_sys::orc::{
        LLVMOrcRegisterJITEventListener,
        LLVMOrcUnregisterJITEventListener,
    }
};

use crate::{
    error::LLVMErrorString,
    lockfree_linked_list::{LockfreeLinkedList, LockfreeLinkedListNode},
    memory_buffer::MemoryBuffer,
    module::Module,
    orc::{
        compile_callback::{lazy_compile_callback, LLVMOrcCreateLazyCompileCallback, LazyCompileCallback, LazyCompiler},
        error::OrcError,
        function_address::FunctionAddress,
        mangled_symbol::{mangle_symbol, MangledSymbol},
        orc_jit_fn::{OrcFunction, UnsafeOrcFn},
        symbol_table::{
            orc_engine_symbol_resolver, GlobalSymbolTable, LocalSymbolTable, LocalSymbolTableInner, SymbolTable
        },
    },
    support::{to_c_str, LLVMString},
    targets::{CodeModel, RelocMode, Target, TargetMachine},
    OptimizationLevel,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompilationMode {
    // Eager compilation is broken for Windows, I believe, so perhaps this should be removed on Windows?
    // https://stackoverflow.com/questions/49866755/rust-llvm-orc-jit-cannot-find-symbol-address
    /// Compile immediately.
    #[cfg_attr(target_os = "windows", doc = "
    # Warning!
    ***This probably will not work on Windows.***
    ")]
    Eager,
    /// Compile on demand. Functions will not be compiled until their first resolution.
    Lazy,
}

// TODO: Update this cfg if any listeners are added that have different requirements.
#[cfg(any(
    any(target_os = "linux", unix),
    all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
))]
#[derive(Debug, Default)]
pub(crate) struct OrcEngineFlags(AtomicU16);

// TODO: Update this cfg if any listeners are added that have different requirements.
#[cfg(any(
    any(target_os = "linux", unix),
    all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
))]
impl OrcEngineFlags {
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self(AtomicU16::new(0))
    }
    
    #[must_use]
    #[inline]
    pub fn get_flag(&self, flag: u16) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire) & flag == flag
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
        let old_flags = self.0.fetch_or(flag, std::sync::atomic::Ordering::AcqRel);
        old_flags & flag != flag
    }
    
    #[inline]
    fn remove_flag(&self, flag: u16) -> bool {
        let old_flags = self.0.fetch_and(!flag, std::sync::atomic::Ordering::AcqRel);
        old_flags & flag != 0
    }
}
// TODO: Update this cfg if any listeners are added that have different requirements.
#[cfg(any(
    any(target_os = "linux", unix),
    all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
))]
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
        // TODO: Update this cfg if any listeners are added that have different requirements.
        #[cfg(any(
            any(target_os = "linux", unix),
            all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
        ))]
        impl OrcEngineFlags {
            $(#[$attr])*
            pub const $flag_const_name: u16 = $flag_value;
            
            $(#[$attr])*
            #[inline]
            pub fn $set_name(&self, on: bool) -> bool {
                self.set_flag(Self::$flag_const_name, on)
            }
            
            $(#[$attr])*
            #[inline]
            pub fn $has_name(&self) -> bool {
                self.get_flag(Self::$flag_const_name)
            }
        }
        // TODO: Update this cfg if any listeners are added that have different requirements.
        #[cfg(any(
            any(target_os = "linux", unix),
            all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
        ))]
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
        // Attributes apply to all items.
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

// TODO: Update this cfg if any listeners are added that have different requirements.
#[cfg(any(
    any(target_os = "linux", unix),
    all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
))]
orc_engine_event_listener_flags_impl!(
    #[cfg(any(target_os = "linux", unix))]
    GDB_LISTENER_REGISTERED         = 1 << 0,
    set_gdb,
    has_gdb,
    gdb,
    add_gdb_registration_listener,
    remove_gdb_registration_listener,
    has_gdb_registration_listener;
    
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"))]
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
    remove_perf_event_listener,
    has_perf_event_listener;
);

#[derive(Debug)]
pub(crate) struct OrcModule {
    pub(crate) handle: LLVMOrcModuleHandle,
    // This just needs to live as long as the OrcModule exists.
    /// Used for per-module symbol resolution with global symbol table fallback.
    pub(crate) _symbol_table: LocalSymbolTable,
}

impl OrcModule {
    pub(crate) fn new(handle: LLVMOrcModuleHandle, symbol_table: LocalSymbolTable) -> Self {
        Self {
            handle,
            _symbol_table: unsafe { std::mem::transmute(symbol_table) },
        }
    }
}

#[derive(Debug)]
pub(crate) struct OrcEngineInner {
    pub(crate) jit_stack: LLVMOrcJITStackRef,
    pub(crate) symbol_table: GlobalSymbolTable,
    pub(crate) modules: RwLock<HashMap<Box<str>, OrcModule>>,
    pub(crate) lazy_compile_callbacks: LockfreeLinkedList<LazyCompileCallback>,
    // TODO: Update this cfg if any listeners are added that have different requirements.
    // The flags do not need to be included if there are no available listeners.
    #[cfg(any(
        any(target_os = "linux", unix),
        all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
    ))]
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
    pub(crate) inner: Arc<OrcEngineInner>,
}

// TODOC (ErisianArchitect): impl OrcEngine
impl OrcEngine {
    #[must_use]
    pub fn with_target_machine(target_machine: TargetMachine) -> Result<Self, OrcError> {
        let jit_stack = unsafe { LLVMOrcCreateInstance(target_machine.as_mut_ptr()) };
        if jit_stack.is_null() {
            return Err(OrcError::CreateInstanceFailure);
        }
        // ownership of target_machine is passed to jit stack successfully
        // so we forget it so that it doesn't get double-freed.
        // This must happen after the `jit_stack.is_null()` check, because
        // it must be properly disposed if creation of the JITStack fails.
        // https://github.com/llvm/llvm-project/blob/1fdec59bffc11ae37eb51a1b9869f0696bfd5312/llvm/include/llvm-c/OrcBindings.h#L42
        std::mem::forget(target_machine);
        Ok(Self {
            inner: Arc::new(OrcEngineInner {
                jit_stack,
                symbol_table: GlobalSymbolTable::new(HashMap::new()),
                modules: RwLock::new(HashMap::new()),
                lazy_compile_callbacks: LockfreeLinkedList::new(),
                // TODO: Update this cfg if any listeners are added that have different requirements.
                // The flags do not need to be included if there are no available listeners.
                #[cfg(any(
                    any(target_os = "linux", unix),
                    all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
                ))]
                flags: OrcEngineFlags::new(),
            })
        })
    }
    
    #[must_use]
    pub fn new(
        optimization_level: OptimizationLevel,
        reloc_mode: RelocMode,
        code_model: CodeModel,
        // If cpu_features is omitted, it defaults to TargetMachine::get_host_cpu_features().
        cpu_features: Option<&str>,
    ) -> Result<Self, OrcError> {
        let default_triple = TargetMachine::get_default_triple();
        let target = Target::from_triple(&default_triple).unwrap();
        // annoyingly, TargetMachine::get_host_cpu_features returns LLVMString, but create_target_machine expects &str.
        // This enum was created so that the fallback could be lazily initialized.
        enum StrOrLLVM<'a> {
            Str(&'a str),
            LLVM(LLVMString),
        }
        impl StrOrLLVM<'_> {
            #[inline(always)]
            fn to_str(&self) -> &str {
                match self {
                    Self::Str(str) => str,
                    Self::LLVM(llvm_string) => llvm_string.to_str().unwrap(),
                }
            }
        }
        let cpu_features = cpu_features
            .map(StrOrLLVM::Str)
            .unwrap_or_else(|| StrOrLLVM::LLVM(TargetMachine::get_host_cpu_features()));
        let target_machine = target.create_target_machine(
            &default_triple,
            TargetMachine::get_host_cpu_name().to_str().unwrap(),
            cpu_features.to_str(),
            optimization_level,
            reloc_mode,
            code_model,
        ).ok_or_else(|| OrcError::CreateTargetMachineFailure)?;
        Self::with_target_machine(target_machine)
    }
    
    #[must_use]
    pub fn new_default() -> Result<Self, OrcError> {
        Self::new(OptimizationLevel::Default, RelocMode::Default, CodeModel::Default, None)
    }
    
    #[must_use]
    #[inline]
    pub fn jit_stack_ref(&self) -> LLVMOrcJITStackRef {
        self.inner.jit_stack
    }
    
    // Unfortunately there is no demangle function, so this is an irreversible operation.
    // There should be a way to demangle it, but that would be up to the user of the api.
    /// Mangles symbol name for use in functions that require a [MangledSymbol].
    /// The [MangledSymbol] that you use in the [OrcEngine] functions must have been created by the same [OrcEngine].
    #[must_use]
    #[inline]
    pub fn mangle_symbol(&self, name: &str) -> MangledSymbol {
        unsafe { mangle_symbol(self.inner.jit_stack, name) }
    }
    
    // TODO (ErisianArchitect): You can get rid of the lifetime of the symbol table if you give it shared ownership of
    //                          the OrcEngine.
    #[must_use]
    #[inline]
    pub fn create_symbol_table<'ctx>(&'ctx self) -> SymbolTable<'ctx> {
        SymbolTable::new(self.inner.jit_stack)
    }
    
    #[must_use]
    #[inline]
    pub fn contains_symbol(&self, name: &str) -> Result<bool, OrcError> {
        Ok(unsafe { self.get_symbol_address(name)? } != 0)
    }
    
    #[must_use]
    #[inline]
    pub fn contains_symbol_in(&self, module: &str, symbol: &str) -> Result<bool, OrcError> {
        Ok(unsafe { self.get_symbol_address_in(module, symbol)? } != 0)
    }
    
    #[must_use]
    pub fn create_mangled_indirect_stub(
        &self,
        mangled_symbol: MangledSymbol,
        address: FunctionAddress,
    ) -> Result<(), OrcError> {
        let err = unsafe {
            LLVMOrcCreateIndirectStub(self.inner.jit_stack, mangled_symbol.as_ptr(), address.0)
        };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::CreateIndirectStubFailure(err_string));
        }
        Ok(())
    }
    
    #[must_use]
    #[inline]
    pub fn create_indirect_stub(&self, name: &str, address: FunctionAddress) -> Result<(), OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.create_mangled_indirect_stub(mangled_symbol, address)
    }
    
    #[must_use]
    pub fn set_mangled_indirect_stub(
        &self,
        mangled_symbol: &MangledSymbol,
        address: FunctionAddress,
    ) -> Result<(), OrcError> {
        let err = unsafe {
            LLVMOrcSetIndirectStubPointer(self.inner.jit_stack, mangled_symbol.as_ptr(), address.0)
        };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::SetIndirectStubFailure(err_string));
        }
        Ok(())
    }
    
    #[must_use]
    #[inline]
    pub fn set_indirect_stub(&self, name: &str, address: FunctionAddress) -> Result<(), OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.set_mangled_indirect_stub(&mangled_symbol, address)
    }
    
    #[must_use]
    #[inline]
    pub fn register_mangled_function(
        &self,
        mangled_symbol: MangledSymbol,
        address: FunctionAddress,
    ) -> Result<(), OrcError> {
        if let Some(found_addr) = self.inner.symbol_table.insert_mangled(mangled_symbol.clone(), address.0) {
            // insert back into the table
            self.inner.symbol_table.insert_mangled(mangled_symbol.clone(), found_addr);
            return Err(OrcError::MangledFunctionAlreadyRegistered(mangled_symbol));
        }
        Ok(())
    }
    
    #[must_use]
    #[inline]
    pub fn register_function(&self, name: &str, address: FunctionAddress) -> Result<(), OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.register_mangled_function(mangled_symbol, address)
    }
    
    #[must_use]
    #[inline]
    pub unsafe fn get_symbol_address(&self, name: &str) -> Result<usize, OrcError> {
        let cname = to_c_str(name);
        let mut symbol_result = 0u64;
        let err = unsafe {
            LLVMOrcGetSymbolAddress(self.inner.jit_stack, &mut symbol_result, cname.as_ptr())
        };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::SymbolAddressLookupFailure(err_string));
        }
        if symbol_result == 0 {
            return Err(OrcError::SymbolNotFound(name.into()));
        }
        Ok(symbol_result as usize)
    }
    
    #[must_use]
    #[inline]
    pub unsafe fn get_symbol_address_in(&self, module: &str, symbol: &str) -> Result<usize, OrcError> {
        let Some(&OrcModule { handle: module_handle, .. }) = self.inner.modules.read().unwrap().get(module) else {
            return Err(OrcError::ModuleNotFound(module.into()));
        };
        let cname = to_c_str(symbol);
        let mut symbol_result = 0u64;
        let err = unsafe {
            LLVMOrcGetSymbolAddressIn(
                self.inner.jit_stack,
                &mut symbol_result,
                module_handle,
                cname.as_ptr(),
            )
        };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::SymbolAddressLookupFailure(err_string));
        }
        if symbol_result == 0 {
            return Err(OrcError::SymbolNotFound(symbol.into()));
        }
        Ok(symbol_result as usize)
    }
    
    #[must_use]
    #[inline]
    pub unsafe fn get_function<'ctx, F: UnsafeOrcFn>(
        &'ctx self,
        name: &str,
    ) -> Result<OrcFunction<'ctx, F>, OrcError> {
        let addr = self.get_symbol_address(name)?;
        Ok(OrcFunction::new(unsafe { std::mem::transmute_copy(&addr) }))
    }
    
    #[must_use]
    #[inline]
    pub unsafe fn get_function_in<'ctx, F: UnsafeOrcFn>(
        &'ctx self,
        module: &str,
        symbol: &str,
    ) -> Result<OrcFunction<'ctx, F>, OrcError> {
        let addr = self.get_symbol_address_in(module, symbol)?;
        Ok(OrcFunction::new(unsafe { std::mem::transmute_copy(&addr) }))
    }
    
    // NOTE: I'm pretty sure eager compilation is useless on Windows because I don't think that you can lookup symbols
    // after compilation.
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
    pub fn add_module(
        &self,
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
        let mut modules = self.inner.modules.write().unwrap();
        if modules.contains_key(name) {
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
            Some(orc_engine_symbol_resolver),
            // This gets a pointer to the LocalSymbolTableInner within the Arc in the LocalSymbolTable.
            // This is used as the context for the module_symbol_resolver.
            // It's okay to cast it to *mut LocalSymbolTableInner from *const LocalSymbolTableInner because it will
            // never be mutated.
            local_table.as_ptr().cast_mut().cast(),
        ) };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(match compilation_mode {
                CompilationMode::Eager => OrcError::AddEagerlyCompiledIRFailure(err_string),
                CompilationMode::Lazy => OrcError::AddLazilyCompiledIRFailure(err_string),
            });
        }
        module.data_layout.borrow_mut().take();
        modules.insert(name.into(), OrcModule::new(handle, local_table));
        Ok(())
    }
    
    // NOTE: I'm pretty sure this is useless on Windows because I don't think that you can lookup symbols from objects
    // added to the engine.
    #[inline] // This is only used in two places (as of writing this comment), so this should be marked as inline.
    fn internal_add_object_from_memory<'guard>(
        &self,
        name: &str,
        memory_buffer: &MemoryBuffer,
        local_symbol_table: Option<SymbolTable>,
        mut modules: RwLockWriteGuard<'guard, HashMap<Box<str>, OrcModule>>,
        // If `modules.contains_key` has already been determined to be true, this will be false.
        // If this is true, that means the check hasn't been performed, and it must be performed.
        check_modules_contains: bool,
    ) -> Result<(), OrcError> {
        let symbol_table = if let Some(symbol_table) = local_symbol_table {
            if symbol_table.jit_stack != self.inner.jit_stack {
                return Err(OrcError::NotOwnedByOrcEngine);
            }
            symbol_table.take_inner()
        } else {
            HashMap::new()
        };
        if check_modules_contains && modules.contains_key(name) {
            return Err(OrcError::RepeatModuleName(name.into()));
        }
        let local_table = LocalSymbolTable::new(self.inner.symbol_table.clone(), symbol_table);
        let mut handle = 0u64;
        let err = unsafe { LLVMOrcAddObjectFile(
            self.inner.jit_stack,
            &mut handle,
            memory_buffer.as_mut_ptr(),
            Some(orc_engine_symbol_resolver),
            // This gets a pointer to the LocalSymbolTableInner within the Arc in the LocalSymbolTable.
            // this is used as the context for the module_symbol_resolver.
            // It's okay to cast it to *mut LocalSymbolTableInner from *const LocalSymbolTableInner because it will never be mutated.
            // The LocalSymbolTable is guaranteed to live as long as the module.
            local_table.as_ptr().cast_mut().cast(),
        ) };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::AddObjectFileFailure(err_string))
        }
        modules.insert(name.into(), OrcModule::new(handle, local_table));
        Ok(())
    }
    
    // NOTE: I'm pretty sure this is useless on Windows because I don't think that you can lookup symbols from objects
    // added to the engine.
    #[must_use]
    #[inline]
    pub fn add_object_from_memory(
        &self,
        name: &str,
        memory_buffer: &MemoryBuffer,
        local_symbol_table: Option<SymbolTable>,
    ) -> Result<(), OrcError> {
        self.internal_add_object_from_memory(
            name,
            memory_buffer,
            local_symbol_table,
            self.inner.modules.write().unwrap(),
            true,
        )
    }
    
    // NOTE: I'm pretty sure this is useless on Windows because I don't think that you can lookup symbols from objects
    // added to the engine.
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
        let modules = self.inner.modules.write().unwrap();
        if modules.contains_key(name) {
            return Err(OrcError::RepeatModuleName(name.into()));
        }
        let mem_buff = MemoryBuffer::create_from_file(object_file_path.as_ref())?;
        self.internal_add_object_from_memory(
            name,
            &mem_buff,
            local_symbol_table,
            modules,
            false,
        )
    }
    
    #[must_use]
    pub fn remove_module(&self, name: &str) -> Result<(), OrcError> {
        let Some(module) = self.inner.modules.write().unwrap().remove(name) else {
            return Err(OrcError::ModuleNotFound(name.into()));
        };
        let err = unsafe { LLVMOrcRemoveModule(self.inner.jit_stack, module.handle) };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::RemoveModuleFailure(err_string));
        }
        Ok(())
    }
    
    #[must_use]
    #[inline]
    pub fn has_module(&self, name: &str) -> bool {
        self.inner.modules.read().unwrap().contains_key(name)
    }
    
    #[must_use]
    pub fn create_lazy_compile_callback<C: LazyCompiler>(&self, compiler: C) -> Result<FunctionAddress, OrcError> {
        let lazy_compiler = LazyCompileCallback::new(self, compiler);
        let node = LockfreeLinkedListNode::new(lazy_compiler);
        // Add the callback node to the callbacks linked list to keep it alive while the OrcEngine is alive.
        unsafe { self.inner.lazy_compile_callbacks.push(&node.next, &*node); }
        let mut ret_addr = 0;
        let err = unsafe {
            LLVMOrcCreateLazyCompileCallback(
                self.jit_stack_ref(),
                &mut ret_addr,
                Some(lazy_compile_callback),
                Box::into_raw(node).cast(),
            )
        };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::CreateLazyCompileCallbackFailure(err_string));
        }
        Ok(FunctionAddress(ret_addr))
    }
}