
/*
TODO (ErisianArchitect):
[ ] Full Orc API support
[ ] Cleanup Code
[ ] Code Review
[ ] Formatting (including removing excess whitespace) (Don't forget lockfree_linked_list.rs)
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
    collections::HashMap, ffi::{c_char, c_void}, path::Path, sync::{Arc, Mutex, RwLock, RwLockWriteGuard}
};

use llvm_sys::orc::{
    LLVMOrcAddEagerlyCompiledIR, LLVMOrcAddLazilyCompiledIR, LLVMOrcAddObjectFile, LLVMOrcCreateIndirectStub, LLVMOrcCreateInstance, LLVMOrcDisposeInstance, LLVMOrcGetSymbolAddress, LLVMOrcGetSymbolAddressIn, LLVMOrcJITStackRef, LLVMOrcModuleHandle, LLVMOrcRemoveModule, LLVMOrcSetIndirectStubPointer, LLVMOrcSymbolResolverFn, LLVMOrcTargetAddress
};

// TODO: Update this cfg if any listeners are added that have different requirements.
#[cfg(any(
    target_family = "unix",
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
    context::Context, error::LLVMErrorString, lockfree_linked_list::{LockfreeLinkedList, LockfreeLinkedListNode}, memory_buffer::MemoryBuffer, module::Module, orc::{
        compile_callback::{lazy_compile_callback, LLVMOrcCreateLazyCompileCallback, LazyCompileCallback, LazyCompiler},
        error::{OrcError, Result},
        function_address::FunctionAddress,
        mangled_symbol::{mangle_symbol, MangledSymbol},
        orc_jit_fn::{OrcFunction, UnsafeOrcFn},
        symbol_table::{
            orc_engine_global_symbol_resolver, orc_engine_local_symbol_resolver, GlobalSymbolTable, GlobalSymbolTableInner, LocalSymbolTable, SymbolTable
        },
    }, support::{to_c_str, LLVMString}, targets::{CodeModel, RelocMode, Target, TargetMachine}, OptimizationLevel
};

/// The [CompilationMode] is used to tell the Orc JIT engine to compile a module either lazily, or eagerly.
/// 
/// Modes:
/// * Eager: Compiles the module immediately.
/// * Lazy: Compiles the module on demand. Functions are not compiled until their materialization is demanded.
/// 
/// You may experience symbol resolution issues with eager compilation.
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

pub(crate) type SymbolResolverFn = extern "C" fn(mangled: *const c_char, context: *mut c_void) -> LLVMOrcTargetAddress;

#[derive(Debug)]
pub(crate) enum InternalSymbolResolver {
    None,
    Global,
    Local(LocalSymbolTable),
}

#[repr(transparent)]
#[derive(Debug)]
pub struct SymbolResolver {
    inner: InternalSymbolResolver,
}

impl SymbolResolver {
    #[must_use]
    #[inline]
    pub(crate) const fn new(inner: InternalSymbolResolver) -> Self {
        Self { inner }
    }
    
    // TODO (ErisianArchitect): This should be used to create a global symbol table fallback.
    #[must_use]
    #[inline]
    pub(crate) const fn global() -> Self {
        Self::new(InternalSymbolResolver::Global)
    }
    
    #[must_use]
    #[inline]
    pub const fn none() -> Self {
        Self::new(InternalSymbolResolver::None)
    }
    
    #[must_use]
    #[inline]
    pub fn local(table: SymbolTable<'_>) -> Self {
        Self::new(
            InternalSymbolResolver::Local(LocalSymbolTable::new(table.take_inner()))
        )
    }
    
    #[must_use]
    #[inline]
    pub(crate) fn into_inner(self) -> InternalSymbolResolver {
        self.inner
    }
}

#[derive(Debug)]
pub(crate) struct SymbolResolverSettings {
    resolver_fn: Option<SymbolResolverFn>,
    context: *mut c_void,
    locals: Option<LocalSymbolTable>,
}

impl InternalSymbolResolver {
    // This part of the API is a little wonky, I'll admit that, but it has the desired outcome.
    pub fn into_settings(
        self,
        // If the SymbolResolver is `Global`, this pointer will become the context that is returned. Otherwise, it is
        // ignored.
        global_table_ptr: *const GlobalSymbolTableInner
    ) -> SymbolResolverSettings {
        match self {
            InternalSymbolResolver::None => SymbolResolverSettings {
                resolver_fn: None,
                context: std::ptr::null_mut(),
                locals: None,
            },
            InternalSymbolResolver::Global => SymbolResolverSettings {
                resolver_fn: Some(orc_engine_global_symbol_resolver),
                context: global_table_ptr.cast_mut().cast(),
                locals: None,
            },
            InternalSymbolResolver::Local(table) => SymbolResolverSettings {
                resolver_fn: Some(orc_engine_local_symbol_resolver),
                context: unsafe { table.as_ptr().cast_mut().cast() },
                locals: Some(table),
            },
        }
    }
}

// TODO: Update this cfg if any listeners are added that have different requirements.
/// The thread-safe flags associated with the OrcEngine.
/// These flags are used to determine:
/// * Which JIT Event Listeners are present.
#[cfg(any(
    target_family = "unix",
    all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
))]
#[repr(transparent)]
#[derive(Debug, Default)]
pub(crate) struct OrcEngineFlags(AtomicU16);

// TODO: Update this cfg if any listeners are added that have different requirements.
#[cfg(any(
    target_family = "unix",
    all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
))]
impl OrcEngineFlags {
    // TODO (ErisianArchitect): Add a method that gets the inner u16.
    /// Creates a new [OrcEngineFlags] with all flags initialized to false.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        // Uses AtomicU16 in case more flags are added in the future.
        Self(AtomicU16::new(0))
    }
    
    /// Determines if the given flag mask is present.
    #[must_use]
    #[inline]
    pub fn get_flag(&self, flag: u16) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire) & flag == flag
    }
    
    /// Sets the flag and returns `true` if the value changed.
    #[inline]
    fn set_flag(&self, flag: u16, on: bool) -> bool {
        if on {
            self.add_flag(flag)
        } else {
            self.remove_flag(flag)
        }
    }
    
    /// Applies `flag` and returns `true` if the value changed.
    #[inline]
    fn add_flag(&self, flag: u16) -> bool {
        let old_flags = self.0.fetch_or(flag, std::sync::atomic::Ordering::AcqRel);
        old_flags & flag != flag
    }
    
    /// Removes `flag` and returns `true` if the value changed.
    #[inline]
    fn remove_flag(&self, flag: u16) -> bool {
        let old_flags = self.0.fetch_and(!flag, std::sync::atomic::Ordering::AcqRel);
        old_flags & flag != 0
    }
}
// TODO: Update this cfg if any listeners are added that have different requirements.
/// This macro is used to implement everything for each given flag for event listeners.
#[cfg(any(
    target_family = "unix",
    all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
))]
macro_rules! orc_engine_event_listener_flags_impl {
    (@impl
        // Attributes applied to all items.
        [
            $(#[$attr:meta])*
        ]
        // The listener name in `listeners.rs`.
        $listener_name:ident,
        // Attributes applied to the flag const.
        $(
            #[$const_attr:meta]
        )*
        // Constant used to store the flag value associated with this event listener.
        $flag_const_name:ident = $flag_value:expr,
        // Attributes applied to the `set` function.
        $(
            #[$set_name_attr:meta]
        )*
        // The name given to the `set` function.
        $set_name:ident,
        // Attributes applied to the `has` function.
        $(
            #[$has_name_attr:meta]
        )*
        // The name given to the `has` function.
        $has_name:ident,
        // Attributes applied to the `add_listener` function.
        $(
            #[$add_listener_name_attr:meta]
        )*
        // The name given to the `add_listener` function.
        $add_listener_name:ident,
        // Attributes applied to the `remove_listener` function.
        $(
            #[$remove_listener_name_attr:meta]
        )*
        // The name given to the `remove_listener` function.
        $remove_listener_name:ident,
        // Attributes applied to the `has_listener` function.
        $(
            #[$has_listener_name_attr:meta]
        )*
        // The name of the `has_listener` function.
        $has_listener_name:ident
    ) => {
        impl OrcEngineFlags {
            $(#[$attr])*
            $(#[$const_attr])*
            pub const $flag_const_name: u16 = $flag_value;
            
            $(#[$attr])*
            $(#[$set_name_attr])*
            #[inline]
            pub fn $set_name(&self, on: bool) -> bool {
                self.set_flag(Self::$flag_const_name, on)
            }
            
            $(#[$attr])*
            $(#[$has_name_attr])*
            #[inline]
            pub fn $has_name(&self) -> bool {
                self.get_flag(Self::$flag_const_name)
            }
        }
        
        impl OrcEngine {
            $(#[$attr])*
            $(#[$add_listener_name_attr])*
            pub fn $add_listener_name(&self) {
                // The `set` function will return `true` if the flag was changed. If it returns false, then this
                // function should return early to prevent a listener from being registered twice.
                if !self.inner.flags.$set_name(true) {
                    return;
                }
                let event_listener = crate::listener::JitEventListener::$listener_name();
                unsafe { LLVMOrcRegisterJITEventListener(self.inner.jit_stack, event_listener.raw) };
            }
            
            $(#[$attr])*
            $(#[$remove_listener_name_attr])*
            pub fn $remove_listener_name(&self) {
                // The `set` function will return `true` if the flag was changed. If it returns false, then this
                // function should return early to prevent a listener from being unregistered twice.
                if !self.inner.flags.$set_name(false) {
                    return;
                }
                let event_listener = crate::listener::JitEventListener::$listener_name();
                unsafe { LLVMOrcUnregisterJITEventListener(self.inner.jit_stack, event_listener.raw) };
            }
            
            $(#[$attr])*
            $(#[$has_listener_name_attr])*
            pub fn $has_listener_name(&self) -> bool {
                self.inner.flags.$has_name()
            }
        }
    };
    ($(
        // Attributes applied to all items.
        $(
            [
                $(#[$attr:meta])+
            ]
        )?
        // The listener name in `listeners.rs`.
        $listener_name:ident,
        // Attributes applied to the flag const.
        $(
            #[$const_attr:meta]
        )*
        // Constant used to store the flag value associated with this event listener.
        const $flag_const_name:ident = $flag_value:expr,
        // Attributes applied to the `set` function.
        $(
            #[$set_name_attr:meta]
        )*
        // The name given to the `set` function.
        $set_name:ident,
        // Attributes applied to the `has` function.
        $(
            #[$has_name_attr:meta]
        )*
        // The name given to the `has` function.
        $has_name:ident,
        // Attributes applied to the `add_listener` function.
        $(
            #[$add_listener_name_attr:meta]
        )*
        // The name given to the `add_listener` function.
        $add_listener_name:ident,
        // Attributes applied to the `remove_listener` function.
        $(
            #[$remove_listener_name_attr:meta]
        )*
        // The name given to the `remove_listener` function.
        $remove_listener_name:ident,
        // Attributes applied to the `has_listener` function.
        $(
            #[$has_listener_name_attr:meta]
        )*
        // The name of the `has_listener` function.
        $has_listener_name:ident;
    )+) => {
        $(
            orc_engine_event_listener_flags_impl!{@impl
                [
                    $( $(#[$attr])* )?
                ]
                $listener_name,
                $(#[$const_attr])*
                $flag_const_name = $flag_value,
                $(#[$set_name_attr])*
                $set_name,
                $(#[$has_name_attr])*
                $has_name,
                $(#[$add_listener_name_attr])*
                $add_listener_name,
                $(#[$remove_listener_name_attr])*
                $remove_listener_name,
                $(#[$has_listener_name_attr])*
                $has_listener_name
            }
        )*
    };
}

// TODO: Update this cfg if any listeners are added that have different requirements.
#[cfg(any(
    target_family = "unix",
    all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
))]
orc_engine_event_listener_flags_impl!(
    [
        #[cfg(target_family = "unix")]
    ]
    gdb,
    /// The GDB Registration Event Listener flag.
    const GDB_LISTENER_REGISTERED         = 1 << 0,
    /// Sets the value for the gdb flag.
    set_gdb,
    /// Checks if the gdb flag is present.
    has_gdb,
    /// Adds the GDB Registration Event Listener.
    add_gdb_registration_listener,
    /// Removes the GDB Registration Event Listener.
    remove_gdb_registration_listener,
    /// Checks if the GDB Registration Event Listener is present.
    has_gdb_registration_listener;
    
    [
        #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"))]
    ]
    intel,
    /// The Intel VTUNE JIT Event Listener flag. Must have `vtune` feature enabled.
    const INTEL_LISTENER_REGISTERED       = 1 << 1,
    /// Sets the value for the intel flag. Must have `vtune` feature enabled.
    set_intel,
    /// Checks if the intel flag is present. Must have `vtune` feature enabled.
    has_intel,
    /// Adds the Intel VTune JIT Event Listener. Must have `vtune` feature enabled.
    add_intel_event_listener,
    /// Removes the Intel VTune JIT Event Listener. Must have `vtune` feature enabled.
    remove_intel_event_listener,
    /// Checks if the Intel VTune JIT Event Listener is present.
    has_intel_event_listener;
    
    [
        #[cfg(target_os = "linux")]
    ]
    oprofile,
    /// The OProfile JIT Event Listener flag.
    const OPROFILE_LISTENER_REGISTERED    = 1 << 2,
    /// Sets the value for the oprofile flag.
    set_oprofile,
    /// Checks if the oprofile flag is present.
    has_oprofile,
    /// Adds the OProfile JIT Event Listener.
    add_oprofile_event_listener,
    /// Removes the OProfile JIT Event Listener.
    remove_oprofile_event_listener,
    /// Checks if the OProfile JIT Event Listener is present.
    has_oprofile_event_listener;
    
    [
        #[cfg(target_os = "linux")]
    ]
    perf,
    /// The Perf JIT Event Listener flag.
    const PERF_LISTENER_REGISTERED        = 1 << 3,
    /// Sets the value of the perf flag.
    set_perf,
    /// Checks if the perf flag is present.
    has_perf,
    /// Adds the Perf JIT Event Listener.
    add_perf_event_listener,
    /// Removes the Perf JIT Event Listener.
    remove_perf_event_listener,
    /// Checks if the Perf JIT Event Listener is present.
    has_perf_event_listener;
);

#[derive(Debug, Default)]
pub(crate) struct KeepAlive {
    keep_alive_list: Vec<Box<dyn std::any::Any>>,
}

impl KeepAlive {
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            keep_alive_list: Vec::new(),
        }
    }
    
    #[inline]
    pub fn push<T: std::any::Any>(&mut self, object: Box<T>) {
        self.keep_alive_list.push(object);
    }
}

/// Internal [OrcModule] for the [OrcEngine].
/// When a [Module] is added to the [OrcEngine], it is transformed into an [OrcModule]. The [OrcModule] owns a local
/// symbol table that is used for symbol resolution fallback. The [OrcEngine] JIT Stack manages the lifetime of the
/// [OrcModule].
#[derive(Debug)]
pub(crate) struct OrcModule {
    /// The LLVM Module Handle, for internal use only.
    pub(crate) handle: LLVMOrcModuleHandle,
    // This just needs to live as long as the OrcModule.
    // TODO (ErisianArchitect): Update this documentation when you update the symbol resolution api.
    /// Used for per-module symbol resolution with optional global symbol table fallback.
    pub(crate) _symbol_table: Option<LocalSymbolTable>,
}

impl OrcModule {
    /// Create a new [OrcModule] from the given [LLVMOrcModuleHandle] with the given [LocalSymbolTable].
    pub(crate) fn new(handle: LLVMOrcModuleHandle, symbol_table: Option<LocalSymbolTable>) -> Self {
        Self {
            handle,
            _symbol_table: symbol_table,
        }
    }
}

// TODO (ErisianArchitect): Continue code review from this point.
/// The managed struct for the LLVM Orc V1 [OrcEngine]. This is a safe wrapper for [LLVMOrcJITStackRef].
#[derive(Debug)]
pub(crate) struct OrcEngineInner {
    // The JITStack is like the Execution Engine of the Orc V1 API.
    /// The [LLVMOrcJITStackRef] is the internal handle to the LLVM Orc JIT stack.
    /// It is needed for most of the functions associated with the Orc JIT engine.
    pub(crate) jit_stack: LLVMOrcJITStackRef,
    // TODO (ErisianArchitect): Update this comment when the symbol resolution api is updated.
    // The global fallback symbol table that functions can be registered to.
    // If a module uses the global symbol table as a fallback, then it will search
    // the global table after searching the local resolutions.
    // Having a per-module global symbol table fallback is likely not desirable, as it would complicate symbol
    // resolution.
    // Symbols are resolved in LIFO order, where the last module that you added is searched first, then the previous
    // module. At each search stage, it will perform local resolution first for external symbols define in the module.
    // Next, it will search the fallback symbol resolver provided for the module. After it has searched the external
    // and local symbols, it will search the next module.
    /// The global symbol table, used for final symbol resolution.
    pub(crate) symbol_table: GlobalSymbolTable,
    /// The internal [OrcModule] storage that owns the [LocalSymbolTable] for each module in order to keep it alive for
    /// symbol resolution.
    pub(crate) modules: RwLock<HashMap<Box<str>, OrcModule>>,
    pub(crate) keep_alive_list: Mutex<KeepAlive>,
    // TODO: Update this cfg if any listeners are added that have different requirements.
    // The flags do not need to be included if there are no available listeners.
    /// The [OrcEngineFlags], which are only available in certain configurations.
    #[cfg(any(
        target_family = "unix",
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

// TODO (ErisianArchitect): Make sure to update this documentation when the Context ownership problem is solved.
/// [OrcEngine] is a (mostly) safe wrapper around the LLVM Orc JIT Stack ([LLVMOrcJITStackRef]).
/// 
/// # Features
/// * User-supplied per-module symbol resolution fallback.
/// * Registration of functions.
/// * Function lookup.
/// * JIT event listeners.
/// * Lazy compilation callbacks.
/// * Indirect stubs.
/// * Object files.
/// * 
/// 
/// # Examples
/// ### Creating an OrcEngine
/// ```rust
/// use inkwell::orc::{
///     error::OrcError,
///     OrcEngine,
/// };
/// use inkwell::targets::{
///     CodeModel,
///     InitializationConfig,
///     RelocMode,
///     Target,
///     TargetMachine,
/// };
/// use inkwell::OptimizationLevel;
/// 
/// fn main() -> Result<(), OrcError> {
///     // It is necessary to initialize the target you wish to create an OrcEngine for.
///     Target::initialize_native(&InitializationConfig::default())
///         .expect("Failed to initialize native target");
///     // Create an OrcEngine from a TargetMachine.
///     let triple = TargetMachine::get_default_triple();
///     let target = Target::from_triple(&triple)?;
///     let target_machine = target.create_target_machine(
///         &triple,
///         TargetMachine::get_host_cpu_name().to_str().unwrap(),
///         TargetMachine::get_host_cpu_features().to_str().unwrap(),
///         OptimizationLevel::Default,
///         RelocMode::Default,
///         CodeModel::Default,
///     ).expect("Failed to create host target machine.");
///     
///     let engine = OrcEngine::with_target_machine(target_machine)?;
///     
///     // Create an OrcEngine from TargetMachine settings.
///     // This will create an OrcEngine for the host target machine.
///     let engine = OrcEngine::new(
///         OptimizationLevel::Default,
///         RelocMode::Default,
///         CodeModel::Default,
///         None,
///     )?;
/// 
///     // Create an OrcEngine with a specific OptimizationLevel, but otherwise
///     // use the default settings.
///     let engine = OrcEngine::with_optimization_level(OptimizationLevel::Aggressive)?;
/// 
///     // Create an OrcEngine with default TargetMachine settings (recommended)
///     let engine = OrcEngine::new_default()?;
///     Ok(())
/// }
/// ```
/// ### Adding Modules
/// ```rust
/// use inkwell::orc::{
///     error::{OrcError, Result},
///     CompilationMode,
///     OrcEngine,
/// };
/// use inkwell::targets::{Target, InitializationConfig};
/// use inkwell::context::Context;
/// fn main() -> Result<()> {
///     // First initialize the Target. Here, we initialize the native
///     // target since that's the one we are running the OrcEngine on.
///     Target::initialize_native(&InitializationConfig::default())
///         .expect("Failed to initialize Target.");
///     
///     let context = Context::create();
///     let module = context.create_module("main");
///     
///     // Here, you would build the module.
///     
///     let engine = OrcEngine::new_default()?;
/// 
///     engine.add_module(
///         // Unique name for the module.
///         "main",
///         module,
///         // Enables lazy compilation. Eager compilation may
///         // be useless on some systems.
///         CompilationMode::Lazy,
///         // optional SymbolTable, which can be created with
///         // `OrcEngine::create_symbol_table`.
///         // The symbol table passed to this function must
///         // have been created by the same OrcEngine.
///         // This SymbolTable is used for fallback local
///         // symbol resolution for this module.
///         None,
///     )?;
///     // If the context is dropped before the engine, it will most
///     // likely cause a segmentation fault.
///     drop(engine);
///     drop(context);
///     Ok(())
/// }
/// ```
/// # Note
/// When a [Module] is added to the [OrcEngine], the [OrcEngine] takes ownership of it. It also requires that the
/// module's [Context] is kept alive longer than the [OrcEngine] is alive. If the [Context] is dropped before the
/// [OrcEngine], it will likely cause a segmentation fault.
#[derive(Debug, Clone)]
pub struct OrcEngine {
    /// The inner smart pointer for the [OrcEngine].
    pub(crate) inner: Arc<OrcEngineInner>,
}

// TODOC (ErisianArchitect): impl OrcEngine
impl OrcEngine {
    /// Creates a new [OrcEngine] for the given [TargetMachine].
    #[must_use]
    pub fn with_target_machine(target_machine: TargetMachine) -> Result<Self, OrcError> {
        // Ensure that the target supports JIT, otherwise the behavior is undefined.
        let target = target_machine.get_target();
        if !target.has_jit() {
            return Err(OrcError::JITNotSupported);
        }
        // ownership of target_machine is passed to jit stack successfully
        // so we forget it so that it doesn't get double-freed.
        // This must happen after the `jit_stack.is_null()` check, because
        // it must be properly disposed if creation of the JITStack fails.
        // https://github.com/llvm/llvm-project/blob/1fdec59bffc11ae37eb51a1b9869f0696bfd5312/llvm/include/llvm-c/OrcBindings.h#L42
        let target_machine = target_machine.take_ownership();
        let jit_stack = unsafe { LLVMOrcCreateInstance(target_machine) };
        if jit_stack.is_null() {
            return Err(OrcError::CreateInstanceFailure);
        }
        let engine = Self {
            inner: Arc::new(OrcEngineInner {
                jit_stack,
                symbol_table: GlobalSymbolTable::new(HashMap::new()),
                modules: RwLock::new(HashMap::new()),
                keep_alive_list: Mutex::new(KeepAlive::new()),
                // TODO: Update this cfg if any listeners are added that have different requirements.
                // The flags do not need to be included if there are no available listeners.
                #[cfg(any(
                    target_family = "unix",
                    all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"),
                ))]
                flags: OrcEngineFlags::new(),
            })
        };
        // Setup the global symbol resolution module.
        let self_context = Context::create();
        let globals_dummy_module = self_context.create_module("globals");
        engine.internal_add_module(
            "globals",
            globals_dummy_module,
            CompilationMode::Lazy,
            SymbolResolver::global(),
        )?;
        // The context must be kept alive while the OrcEngine is alive.
        engine.keep_alive(self_context);
        Ok(engine)
    }
    
    /// Creates a new [OrcEngine] with the given [TargetMachine] configuration options.
    /// 
    /// If `cpu_features` is [None], it will fallback to the host cpu features.
    #[must_use]
    pub fn new(
        optimization_level: OptimizationLevel,
        reloc_mode: RelocMode,
        code_model: CodeModel,
        cpu_features: Option<&str>,
    ) -> Result<Self, OrcError> {
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
                    &Self::Str(str) => str,
                    Self::LLVM(llvm_string) => llvm_string.to_str().unwrap(),
                }
            }
        }
        let cpu_features = cpu_features
            .map(StrOrLLVM::Str)
            .unwrap_or_else(|| StrOrLLVM::LLVM(TargetMachine::get_host_cpu_features()));
        let default_triple = TargetMachine::get_default_triple();
        let target = Target::from_triple(&default_triple).unwrap();
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
    
    /// Create a new [OrcEngine] with the given [OptimizationLevel].
    /// 
    /// This is equivalent to [OrcEngine::new] with the given [OptimizationLevel] and default settings:
    /// ```rust
    /// use inkwell::orc::OrcEngine;
    /// use inkwell::targets::{CodeModel, RelocMode};
    /// use inkwell::OptimizationLevel;
    /// use inkwell::targets::{Target, InitializationConfig};
    /// 
    /// Target::initialize_native(&InitializationConfig::default())
    ///     .expect("Failed to initialize native target");
    /// 
    /// // [Your optimization level here]
    /// let optimization_level = OptimizationLevel::Default;
    /// let engine = OrcEngine::with_optimization_level(optimization_level)
    ///     .expect("Failed to create OrcEngine.");
    /// // is equivalent to:
    /// let engine = OrcEngine::new(
    ///     optimization_level,
    ///     RelocMode::Default,
    ///     CodeModel::Default,
    ///     None,
    /// ).expect("Failed to create OrcEngine.");
    /// ```
    #[must_use]
    #[inline]
    pub fn with_optimization_level(optimization_level: OptimizationLevel) -> Result<Self> {
        Self::new(
            optimization_level,
            RelocMode::Default,
            CodeModel::Default,
            None,
        )
    }
    
    /// Creates a new [OrcEngine] with the default [TargetMachine] settings.
    #[must_use]
    #[inline]
    pub fn new_default() -> Result<Self, OrcError> {
        Self::new(OptimizationLevel::Default, RelocMode::Default, CodeModel::Default, None)
    }
    
    #[must_use]
    pub fn is_module_name_reserved(name: &str) -> bool {
        match name {
            "global" => true,
            _ => false,
        }
    }
    
    /// The internal [LLVMOrcJITStackRef]. Use at your own risk.
    #[must_use]
    #[inline]
    pub fn jit_stack_ref(&self) -> LLVMOrcJITStackRef {
        self.inner.jit_stack
    }
    
    /// Keep objects alive for the duration of the OrcEngine's lifetime.
    #[inline]
    pub(crate) fn keep_alive<T: std::any::Any>(&self, object: T) {
        self.inner.keep_alive_list.lock().unwrap().push(Box::new(object));
    }
    
    #[inline]
    pub(crate) fn keep_alive_boxed<T: std::any::Any>(&self, object: Box<T>) {
        self.inner.keep_alive_list.lock().unwrap().push(object);
    }
    
    // Unfortunately there is no demangle function, so this is an irreversible operation.
    // There may be a way to demangle it, but that would be up to the user of the api.
    /// Mangles symbol name for use in functions that require a [MangledSymbol].
    /// The [MangledSymbol] that you use in the [OrcEngine] functions must have been created by the same [OrcEngine].
    #[must_use]
    #[inline]
    pub fn mangle_symbol(&self, name: &str) -> MangledSymbol {
        unsafe { mangle_symbol(self.inner.jit_stack, name) }
    }
    
    // TODO (ErisianArchitect): You can get rid of the lifetime of the symbol table if you give it shared ownership of
    //                          the OrcEngine.
    // TODOC (ErisianArchitect): Write documentation for this after updating symbol resolution API.
    #[must_use]
    #[inline]
    pub fn create_symbol_table<'ctx>(&'ctx self) -> SymbolTable<'ctx> {
        SymbolTable::new(self.inner.jit_stack)
    }
    
    /// Checks if the symbol with the given name is present in the [OrcEngine].
    #[must_use]
    #[inline]
    pub fn contains_symbol(&self, name: &str) -> Result<bool, OrcError> {
        Ok(unsafe { self.get_symbol_address(name)? } != 0)
    }
    
    /// Checks if the symbol with the given name is present in the given module.
    /// If the module does not exist, this will return an error.
    #[must_use]
    #[inline]
    pub fn contains_symbol_in(&self, module: &str, symbol: &str) -> Result<bool, OrcError> {
        Ok(unsafe { self.get_symbol_address_in(module, symbol)? } != 0)
    }
    
    /// Creates an indirect stub with a pre-mangled symbol name and address.
    /// The [MangledSymbol] that you provide *must* have been created by this [OrcEngine]. If it was not created from
    /// the same [OrcEngine], the behavior is indeterminable.
    /// 
    /// An indirect stub is a function whose address can be swapped out at any time. You can swap out the address with
    /// [OrcEngine::set_indirect_stub] and [OrcEngine::set_mangled_indirect_stub].
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
    
    /// Creates a new indirect stub with the given name and address.
    /// 
    /// An indirect stub is a function whose address can be swapped out at any time. You can swap out the address with
    /// [OrcEngine::set_indirect_stub] and [OrcEngine::set_mangled_indirect_stub].
    #[must_use]
    #[inline]
    pub fn create_indirect_stub(&self, name: &str, address: FunctionAddress) -> Result<(), OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.create_mangled_indirect_stub(mangled_symbol, address)
    }
    
    /// Sets the address of the indirect stub with the given mangled name.
    /// 
    /// An indirect stub is a function whose address can be swapped out at any time. You can create/register one with
    /// [OrcEngine::create_indirect_stub] and [OrcEngine::create_mangled_indirect_stub].
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
    
    /// Sets the address of the indirect stub with the given name.
    /// 
    /// An indirect stub is a function whose address can be swapped out at any time. You can create/register one with
    /// [OrcEngine::create_indirect_stub] and [OrcEngine::create_mangled_indirect_stub].
    #[must_use]
    #[inline]
    pub fn set_indirect_stub(&self, name: &str, address: FunctionAddress) -> Result<(), OrcError> {
        let mangled_symbol = self.mangle_symbol(name);
        self.set_mangled_indirect_stub(&mangled_symbol, address)
    }
    
    /// Register a function with the given mangled name. This function will exist in the global fallback symbol table.
    #[inline]
    pub fn register_mangled_function(
        &self,
        mangled_symbol: MangledSymbol,
        address: FunctionAddress,
    ) -> Option<FunctionAddress> {
        let old = self.inner.symbol_table.insert(mangled_symbol, address.0);
        old.map(|old| unsafe { FunctionAddress::from_raw(old) })
    }
    
    /// Register a function with the given name. This function will exist in the global fallback symbol table.
    #[must_use]
    #[inline]
    pub fn register_function(&self, name: &str, address: FunctionAddress) -> Option<FunctionAddress> {
        let mangled_symbol = self.mangle_symbol(name);
        self.register_mangled_function(mangled_symbol, address)
    }
    
    /// Register multiple mangled functions at the same time. If the [MangledSymbol] is already present in the global
    /// table, it will be overwritten.
    #[inline]
    pub fn register_mangled_functions<It: IntoIterator<Item = (MangledSymbol, FunctionAddress)>>(
        &self,
        functions: It,
    ) {
        self.inner.symbol_table.insert_many(
            functions.into_iter().map(|(symbol, function)| (
                symbol,
                function.0,
            )));
    }
    
    /// Register multiple functions at the same time. If the function with the given name is already present in the
    /// global table, it will be overwritten.
    #[inline]
    pub fn register_functions<S: AsRef<str>, It: IntoIterator<Item = (S, FunctionAddress)>>(
        &self,
        functions: It,
    ) {
        self.inner.symbol_table.insert_many(
            functions.into_iter().map(move |(name, function)| (
                self.mangle_symbol(name.as_ref()),
                function.0,
            ))
        );
    }
    
    #[inline]
    pub fn register_mangled_functions_from_slice(&self, functions: &[(MangledSymbol, FunctionAddress)]) {
        self.register_mangled_functions(functions.iter().cloned());
    }
    
    #[inline]
    pub fn register_functions_from_slice<S: AsRef<str>>(&self, functions: &[(S, FunctionAddress)]) {
        self.register_functions(functions.iter().map(|(name, function)| (name, *function)));
    }
    
    /// Gets the address of the symbol with the given name. This is an unsafe function because raw addresses are unsafe
    /// territory. You are not meant to work with raw addresses unless absolutely necessary.
    /// 
    /// For most cases, you can use [OrcEngine::get_function] or [OrcEngine::get_function_in], which will return a safe
    /// function pointer wrapper that you can use to invoke the function.
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
    
    /// Gets the address of the symbol with the given name in the module with the given name. This is an unsafe
    /// function because raw addresses are unsafe territory. You are not meant to work with raw addresses unless
    /// absolutely necessary.
    /// 
    /// For most cases, you can use [OrcEngine::get_function] or [OrcEngine::get_function_in], which will return a safe
    /// function pointer wrapper that you can use to invoke the function.
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
    
    /// Get a function within this [OrcEngine].
    #[must_use]
    #[inline]
    pub unsafe fn get_function<'ctx, F: UnsafeOrcFn>(
        &'ctx self,
        name: &str,
    ) -> Result<OrcFunction<'ctx, F>, OrcError> {
        let addr = self.get_symbol_address(name)?;
        Ok(OrcFunction::<'ctx, F>::new(unsafe { std::mem::transmute_copy(&addr) }))
    }
    
    /// Get a function within this [OrcEngine] from the module with the given name.
    #[must_use]
    #[inline]
    pub unsafe fn get_function_in<'ctx, F: UnsafeOrcFn>(
        &'ctx self,
        module: &str,
        name: &str,
    ) -> Result<OrcFunction<'ctx, F>, OrcError> {
        let addr = self.get_symbol_address_in(module, name)?;
        Ok(OrcFunction::new(unsafe { std::mem::transmute_copy(&addr) }))
    }
    
    pub(crate) fn internal_add_module(
        &self,
        name: &str,
        module: Module<'_>,
        compilation_mode: CompilationMode,
        symbol_resolver: SymbolResolver,
    ) -> Result<(), OrcError> {
        let mut modules = self.inner.modules.write().unwrap();
        // Return an error if the name has already been registered. You can't have two modules with the same name, and you
        // can't overwrite modules. It's improper.
        if Self::is_module_name_reserved(name) {
            return Err(OrcError::ReservedModuleName(name.into()));
        }
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
        drop(module.data_layout.borrow_mut().take());
        let SymbolResolverSettings {
            resolver_fn,
            context: resolver_ctx,
            locals,
        } = symbol_resolver.into_inner().into_settings(self.inner.symbol_table.as_ptr());
        let add_compiled_ir_fn = match compilation_mode {
            CompilationMode::Eager => LLVMOrcAddEagerlyCompiledIR,
            CompilationMode::Lazy => LLVMOrcAddLazilyCompiledIR,
        };
        let mut handle = 0;
        let err = unsafe { add_compiled_ir_fn(
            self.inner.jit_stack,
            &mut handle,
            module.as_mut_ptr(),
            resolver_fn,
            resolver_ctx,
        ) };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(match compilation_mode {
                CompilationMode::Eager => OrcError::AddEagerlyCompiledIRFailure(err_string),
                CompilationMode::Lazy => OrcError::AddLazilyCompiledIRFailure(err_string),
            });
        }
        modules.insert(name.into(), OrcModule::new(handle, locals));
        Ok(())
    }
    
    // TODO (ErisianArchitect): I'm not entirely sure about the symbol resolution behavior, so I want to update this
    //                          documentation after doing some experiments to figure out the order.
    // NOTE: I'm pretty sure eager compilation is useless on Windows because I don't think that you can lookup symbols
    // after compilation.
    /// Adds a module to the Orc JIT engine. The module is considered finalized, and cannot be modified after being
    /// added to the engine.
    /// Use [CompilationMode::Eager] to eagerly compile the module (compilation is immediate).
    /// Use [CompilationMode::Lazy] to lazily compile the module (compilation on demand).
    /// 
    /// `locals` is for local symbol resolution fallback (optional).
    /// 
    /// The module name must be unique (no other module added to this engine by that name).
    #[must_use]
    pub fn add_module(
        &self,
        name: &str,
        module: Module<'_>,
        compilation_mode: CompilationMode,
        locals: Option<SymbolTable<'_>>,
    ) -> Result<(), OrcError> {
        self.internal_add_module(
            name,
            module,
            compilation_mode,
            locals.map(SymbolResolver::local).unwrap_or_else(SymbolResolver::none),
        )
    }
    
    // NOTE: I'm pretty sure this is useless on Windows because I don't think that you can lookup symbols from objects
    // added to the engine.
    /// Internal function for adding an object from memory. Utilized by [OrcEngine::add_object_from_memory] and
    /// [OrcEngine::add_object_file].
    #[inline] // This is only used in two places (as of writing this comment), so this should be marked as inline.
    fn internal_add_object_from_memory(
        &self,
        name: &str,
        memory_buffer: &MemoryBuffer,
        symbol_resolver: SymbolResolver,
        mut modules: RwLockWriteGuard<'_, HashMap<Box<str>, OrcModule>>,
        // If `modules.contains_key` has already been determined to be true, this will be false.
        // If this is true, that means the check hasn't been performed, and it must be performed.
        needs_name_check: bool,
    ) -> Result<(), OrcError> {
        if needs_name_check {
            if Self::is_module_name_reserved(name) {
                return Err(OrcError::ReservedModuleName(name.into()));
            }
            if modules.contains_key(name) {
                return Err(OrcError::RepeatModuleName(name.into()));
            }
        }
        let SymbolResolverSettings {
            resolver_fn,
            context: resolver_ctx,
            locals,
        } = symbol_resolver.into_inner().into_settings(self.inner.symbol_table.as_ptr());
        let mut handle = 0;
        let err = unsafe { LLVMOrcAddObjectFile(
            self.inner.jit_stack,
            &mut handle,
            memory_buffer.as_mut_ptr(),
            resolver_fn,
            // This gets a pointer to the LocalSymbolTableInner within the Arc in the LocalSymbolTable.
            // this is used as the context for the module_symbol_resolver.
            // It's okay to cast it to *mut LocalSymbolTableInner from *const LocalSymbolTableInner because it will never be mutated.
            // The LocalSymbolTable is guaranteed to live as long as the module.
            resolver_ctx,
        ) };
        if !err.is_null() {
            let err_string = unsafe { LLVMErrorString::new(err) };
            return Err(OrcError::AddObjectFileFailure(err_string))
        }
        modules.insert(name.into(), OrcModule::new(handle, locals));
        Ok(())
    }
    
    // NOTE: I'm pretty sure this is useless on Windows because I don't think that you can lookup symbols from objects
    // added to the engine.
    /// Add an object (as in "object file") from memory to the [OrcEngine].
    #[must_use]
    #[inline]
    pub fn add_object_from_memory(
        &self,
        name: &str,
        memory_buffer: &MemoryBuffer,
        locals: Option<SymbolTable<'_>>,
    ) -> Result<(), OrcError> {
        self.internal_add_object_from_memory(
            name,
            memory_buffer,
            locals.map(SymbolResolver::local).unwrap_or_else(SymbolResolver::none),
            self.inner.modules.write().unwrap(),
            // Check that the module hasn't already been registered.
            true,
        )
    }
    
    // NOTE: I'm pretty sure this is useless on Windows because I don't think that you can lookup symbols from objects
    // added to the engine.
    /// Add an object file to the [OrcEngine].
    #[must_use]
    pub fn add_object_file<P: AsRef<Path>>(
        &self,
        name: &str,
        object_file_path: P,
        locals: Option<SymbolTable<'_>>,
    ) -> Result<(), OrcError> {
        let modules = self.inner.modules.write().unwrap();
        // Return an error if the name has already been registered. You can't have two modules with the same name, and you
        // can't overwrite modules. It's improper.
        if Self::is_module_name_reserved(name) {
            return Err(OrcError::ReservedModuleName(name.into()));
        }
        if modules.contains_key(name) {
            return Err(OrcError::RepeatModuleName(name.into()));
        }
        let mem_buff = MemoryBuffer::create_from_file(object_file_path.as_ref())?;
        self.internal_add_object_from_memory(
            name,
            &mem_buff,
            locals.map(SymbolResolver::local).unwrap_or_else(SymbolResolver::none),
            modules,
            // Don't check that the module has already been registered because that check has already been performed.
            false,
        )
    }
    
    /// Remove a module from the [OrcEngine]. The module with the given name must exist in the engine.
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
    
    /// Check if the [OrcEngine] contains the module with the given name.
    #[must_use]
    #[inline]
    pub fn has_module(&self, name: &str) -> bool {
        self.inner.modules.read().unwrap().contains_key(name)
    }
    
    // TODO (ErisianArchitect): More extensive example needed.
    /// Create a lazy compile callback, which creates a trampoline function that will call your callback in order to 
    /// compile the final function for use in the OrcEngine. You can use any method for compiling the function.
    /// 
    /// The typical pattern is the use a closure/function that takes an [OrcEngine] as input and returns a
    /// [FunctionAddress]. The [FunctionAddress] can come from anywhere, so long as it points to a valid function. The
    /// lazy compile callback stub will then have its address swapped with the address returned from the lazy compile callback.
    /// You can even use the [OrcEngine] itself to compile the code, or you could return the address to a pre-existing
    /// function in Rust.
    /// 
    /// # Example
    /// ```rust
    /// use inkwell::{
    ///     orc::OrcEngine,
    ///     orc::function_address::FunctionAddress,
    ///     fn_addr,
    /// };
    /// pub unsafe extern "C" fn compiled_function_example() {
    ///     println!("Called the compiled function.");
    /// }
    /// inkwell::targets::Target::initialize_native(&inkwell::targets::InitializationConfig::default())
    ///     .expect("Failed to initialize native target");
    /// let engine = OrcEngine::new_default().expect("Failed to create OrcEngine.");
    /// let lazy_callback = engine.create_lazy_compile_callback(|engine: OrcEngine| {
    ///     fn_addr!(compiled_function_example)
    /// }).expect("Failed to create lazy compile callback.");
    /// engine.register_function("my_lazy_callback", lazy_callback);
    /// // now `my_lazy_callback` is a globally registered function. You
    /// // can now call the function in your JIT code in order to execute the lazy compiler.
    /// ```
    #[must_use]
    pub fn create_lazy_compile_callback<C: LazyCompiler>(&self, compiler: C) -> Result<FunctionAddress, OrcError> {
        // I think this should reduce code bloat in cases where this function has many monomorphized variants.
        fn inner(engine: &OrcEngine, lazy_compiler: LazyCompileCallback) -> Result<FunctionAddress, OrcError> {
            let keep_alive = Box::new(lazy_compiler);
            let mut ret_addr = 0;
            let err = unsafe {
                LLVMOrcCreateLazyCompileCallback(
                    engine.jit_stack_ref(),
                    &mut ret_addr,
                    Some(lazy_compile_callback),
                    &*keep_alive as *const _ as *mut _,
                )
            };
            if !err.is_null() {
                let err_string = unsafe { LLVMErrorString::new(err) };
                return Err(OrcError::CreateLazyCompileCallbackFailure(err_string));
            }
            engine.keep_alive_boxed(keep_alive);
            Ok(FunctionAddress(ret_addr))
        }
        let lazy_compiler = LazyCompileCallback::new(self, compiler);
        inner(self, lazy_compiler)
    }
}