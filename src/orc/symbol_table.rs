use std::{collections::HashMap, os::raw::c_void, rc::Rc, sync::{Arc, RwLock}};

use libc::c_char;
use llvm_sys::orc::LLVMOrcTargetAddress;

use crate::orc::{function_address::FunctionAddress, mangled_symbol::{mangle_symbol, MangledSymbol}, OrcEngineInner};

// TODO (ErisianArchitect): Create IntoSymbolTable trait and implement for some types.
//                          IntoSymbolTable should be used to create a HashMap<MangledSymbol, u64>.

pub(crate) type SymbolResolverFn = extern "C" fn(mangled: *const c_char, context: *mut c_void) -> LLVMOrcTargetAddress;

/// Wrapper around [RwLock<HashMap<MangledSymbol, LLVMOrcTargetAddress>>].
#[derive(Debug)]
pub(crate) struct GlobalSymbolTableInner {
    pub(crate) table: RwLock<HashMap<MangledSymbol, LLVMOrcTargetAddress>>,
}

impl GlobalSymbolTableInner {
    /// Gets the address of the symbol if it has been registered. Returns [None] if the symbol doesn't exist in the
    /// table.
    #[must_use]
    #[inline]
    pub fn get_symbol(&self, symbol: &MangledSymbol) -> Option<LLVMOrcTargetAddress> {
        self.table.read().unwrap().get(symbol).cloned()
    }
}

/// The global symbol table used by the orc engine to hold symbols accessible to all modules via symbol resolution
/// fallback.
#[repr(transparent)]
#[derive(Debug)]
pub(crate) struct GlobalSymbolTable {
    // `GlobalSymbolTableInner` is placed inside a `Box` so that the pointer to the box can be retrieved and used as
    // the context to the symbol resolver.
    pub(crate) inner: Box<GlobalSymbolTableInner>,
}

impl GlobalSymbolTable {
    /// Create a new [GlobalSymbolTable] from the given hashmap.
    #[must_use]
    pub fn new(symbol_table: HashMap<MangledSymbol, LLVMOrcTargetAddress>) -> Self {
        Self {
            inner: Box::new(GlobalSymbolTableInner { 
                table: RwLock::new(symbol_table),
            }),
        }
    }
    
    /// Insert a symbol with the given address into the table.
    #[inline]
    pub fn insert(
        &self,
        mangled_symbol: MangledSymbol,
        addr: LLVMOrcTargetAddress,
    ) -> Option<LLVMOrcTargetAddress> {
        self.inner.table.write().unwrap().insert(mangled_symbol, addr)
    }
    
    /// Insert many symbols simultaneously from an iterator.
    #[inline]
    pub fn insert_many<It: IntoIterator<Item = (MangledSymbol, LLVMOrcTargetAddress)>>(&self, symbols: It) {
        self.inner.table.write().unwrap().extend(symbols);
    }
    
    /// Gets the pointer to the symbol table that is to be used as the symbol resolver context.
    #[must_use]
    #[inline]
    pub(crate) fn as_ptr(&self) -> *const GlobalSymbolTableInner {
        &*self.inner
    }
}

/// Wrapper around [HashMap<MangledSymbol, LLVMOrcTargetAddress>] used for local symbol resolution fallback.
#[derive(Debug)]
pub(crate) struct LocalSymbolTableInner {
    local_table: HashMap<MangledSymbol, LLVMOrcTargetAddress>,
}

impl LocalSymbolTableInner {
    /// First searches the local table for the symbol, then if not found, searches the global table.
    /// Returns None if the symbol was not found in either table.
    pub(crate) fn get_symbol(&self, mangled_symbol: &MangledSymbol) -> Option<LLVMOrcTargetAddress> {
        self.local_table
            .get(mangled_symbol).cloned()
    }
}

/// The local symbol table for a single module.
#[repr(transparent)]
#[derive(Debug)]
pub(crate) struct LocalSymbolTable {
    // Placed inside a box so that the pointer can be retrieved.
    inner: Box<LocalSymbolTableInner>,
}

impl LocalSymbolTable {
    /// Create a new [LocalSymbolTable] from the given hashmap.
    #[must_use]
    pub(crate) fn new(local_table: HashMap<MangledSymbol, LLVMOrcTargetAddress>) -> Self {
        Self {
            inner: Box::new(LocalSymbolTableInner {
                local_table,
            }),
        }
    }
    
    /// Get the pointer to the inner table.
    #[must_use]
    #[inline]
    pub(crate) unsafe fn as_ptr(&self) -> *const LocalSymbolTableInner {
        &*self.inner
    }
}

/// A symbol table used to store addresses to user functions.
#[derive(Debug)]
pub struct SymbolTable {
    // It's safe for SymbolTable to have the JITStackRef because it is tied to the lifetime of the OrcEngine.
    // The JITStack is needed for name mangling.
    pub(crate) orc_engine: Arc<OrcEngineInner>,
    pub(crate) symbols: HashMap<MangledSymbol, LLVMOrcTargetAddress>,
}

impl SymbolTable {
    /// Create a new [SymbolTable] for the given Orc Engine.
    #[must_use]
    #[inline]
    pub(crate) fn new(orc_engine: Arc<OrcEngineInner>) -> Self {
        Self {
            orc_engine,
            symbols: HashMap::new(),
        }
    }
    
    /// Register many symbols from pre-mangled names and function addresses.
    pub fn register_mangled_from_iter<It: IntoIterator<Item = (MangledSymbol, FunctionAddress)>>(
        &mut self,
        symbols: It,
    ) {
        self.symbols.extend(symbols.into_iter().map(|(mangled, addr)| (mangled, addr.0)));
    }
    
    /// Register many symbols by name and address.
    pub fn register_from_iter<S: AsRef<str>, It: IntoIterator<Item = (S, FunctionAddress)>>(&mut self, symbols: It) {
        let jit_stack = self.orc_engine.jit_stack;
        self.symbols.extend(symbols.into_iter().map(move |(name, addr)| (
            unsafe { mangle_symbol(jit_stack, name.as_ref()) },
            addr.0,
        )));
    }
    
    /// Register a pre-mangled symbol.
    #[inline]
    pub fn register_mangled(
        &mut self,
        mangled_symbol: MangledSymbol,
        address: FunctionAddress,
    ) -> Option<FunctionAddress> {
        let old = self.symbols.insert(mangled_symbol, address.0);
        old.map(|old| unsafe { FunctionAddress::from_raw(old) })
    }
    
    /// Register a symbol witht he given name.
    #[inline]
    pub fn register(&mut self, name: &str, address: FunctionAddress) -> Option<FunctionAddress> {
        let mangled_symbol = unsafe { mangle_symbol(self.orc_engine.jit_stack, name) };
        self.register_mangled(mangled_symbol, address)
    }
    
    /// Register many mangled symbols from a slice.
    #[inline]
    pub fn register_mangled_from_slice(&mut self, functions: &[(MangledSymbol, FunctionAddress)]) {
        self.register_mangled_from_iter(functions.iter().cloned());
    }
    
    /// Register many symbols from a slice.
    #[inline]
    pub fn register_from_slice<S: AsRef<str>>(&mut self, functions: &[(S, FunctionAddress)]) {
        self.register_from_iter(functions.iter().map(|(name, function)| (name.as_ref(), *function)));
    }
    
    /// Checks if the symbol table contains the given [MangledSymbol].
    #[must_use]
    #[inline]
    pub fn contains_mangled(&self, mangled_symbol: &MangledSymbol) -> bool {
        self.symbols.contains_key(mangled_symbol)
    }
    
    /// Checks if the symbol table contains a symbol with the given name.
    #[must_use]
    #[inline]
    pub fn contains(&self, name: &str) -> bool {
        let mangled_symbol = unsafe { mangle_symbol(self.orc_engine.jit_stack, name) };
        self.contains_mangled(&mangled_symbol)
    }
    
    /// Take the inner hashmap.
    #[must_use]
    #[inline]
    pub(crate) fn take_inner(self) -> HashMap<MangledSymbol, LLVMOrcTargetAddress> {
        self.symbols
    }
}

// pub type LLVMOrcSymbolResolverFn = Option<extern "C" fn(_: *const c_char, _: *mut c_void) -> u64>;
/// This function can be passed as LLVMOrcSymbolResolverFn in LLVMOrcAddEagerCompiledIR and LLVMOrcAddLazilyCompiledIR
/// for global symbol resolution.
pub(crate) extern "C" fn orc_engine_global_symbol_resolver(
    mangled_cstr: *const c_char,
    context: *mut c_void,
) -> LLVMOrcTargetAddress {
    let sym_table_ptr: *const GlobalSymbolTableInner = context.cast();
    let globals = unsafe { sym_table_ptr.as_ref() };
    let Some(globals) = globals else {
        // This is an error, but we cannot panic here.
        eprintln!("Error: Context for global symbol resolver was null.");
        return 0;
    };
    // Create a temporary MangledSymbol value based on the provided cstr. This MangledSymbol will be prevented from
    // dropping after the symbol is looked up.
    let temp_mangled_symbol = unsafe { MangledSymbol::from_mangled_cstr(mangled_cstr as _) };
    // returning 0 means the symbol was not found.
    let result = globals.get_symbol(&temp_mangled_symbol).unwrap_or(0);
    // destructure the MangledSymbol and Arc in order to forget about the inner value so that it is not double-freed.
    // the symbol resolution system owns the mangled string.
    let MangledSymbol { symbol } = temp_mangled_symbol;
    if let Some(inner) = Rc::into_inner(symbol) {
        std::mem::forget(inner);
    } else {
        eprintln!("Error: Somehow MangledSymbol was not exclusive during symbol resolution.");
    }
    result
}

// pub type LLVMOrcSymbolResolverFn = Option<extern "C" fn(_: *const c_char, _: *mut c_void) -> u64>;
/// This function can be passed as LLVMOrcSymbolResolverFn in LLVMOrcAddEagerCompiledIR and LLVMOrcAddLazilyCompiledIR
/// for local symbol resolution.
pub(crate) extern "C" fn orc_engine_local_symbol_resolver(
    mangled_cstr: *const c_char,
    context: *mut c_void,
) -> LLVMOrcTargetAddress {
    let sym_table_ptr: *const LocalSymbolTableInner = context.cast();
    let locals = unsafe { sym_table_ptr.as_ref() };
    let Some(locals) = locals else {
        // This is an error, but we cannot panic here.
        eprintln!("Error: Context for the local symbol resolver was null.");
        return 0;
    };
    // Create a temporary MangledSymbol value based on the provided cstr. This MangledSymbol will be prevented from
    // dropping after the symbol is looked up.
    let temp_mangled_symbol = unsafe { MangledSymbol::from_mangled_cstr(mangled_cstr as _) };
    // returning 0 means the symbol was not found.
    let result = locals.get_symbol(&temp_mangled_symbol).unwrap_or(0);
    // destructure the MangledSymbol and Arc in order to forget about the inner value so that it is not double-freed.
    // the symbol resolution system owns the mangled string.
    let MangledSymbol { symbol } = temp_mangled_symbol;
    if let Some(inner) = Rc::into_inner(symbol) {
        std::mem::forget(inner);
    } else {
        eprintln!("Error: Somehow MangledSymbol was not exclusive during symbol resolution.");
    }
    result
}