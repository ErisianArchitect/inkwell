use std::{collections::HashMap, marker::PhantomData, mem::transmute_copy, os::raw::c_void, sync::{Arc, RwLock}};

use libc::c_char;
use llvm_sys::orc::{LLVMOrcJITStackRef, LLVMOrcTargetAddress};

use crate::{orc::{mangled_symbol::{mangle_symbol, MangledSymbol}, orc_jit_fn::UnsafeOrcFn}};

// TODO (ErisianArchitect): Create IntoSymbolTable trait and implement for some types.
//                          IntoSymbolTable should be used to create a HashMap<MangledSymbol, u64>.

// TODO (ErisianArchitect): Make stuff thread safe.

#[derive(Debug)]
pub(crate) struct GlobalSymbolTableInner {
    pub(crate) table: RwLock<HashMap<MangledSymbol, LLVMOrcTargetAddress>>,
}

// TODOC (ErisianArchitect): struct GlobalSymbolTable
#[repr(transparent)]
#[derive(Debug, Clone)]
pub(crate) struct GlobalSymbolTable {
    pub(crate) inner: Arc<GlobalSymbolTableInner>,
}

// pub struct MultiInsert<'guard> {
//     table: RwLockWriteGuard<'guard, HashMap<MangledSymbol, LLVMOrcTargetAddress>>
// }

// TODOC (ErisianArchitect): impl GlobalSymbolTable
impl GlobalSymbolTable {
    #[must_use]
    pub(crate) fn new(symbol_table: HashMap<MangledSymbol, LLVMOrcTargetAddress>) -> Self {
        Self {
            inner: Arc::new(GlobalSymbolTableInner { 
                table: RwLock::new(symbol_table),
            }),
        }
    }
    
    #[inline]
    pub fn insert_mangled(&self, mangled_symbol: MangledSymbol, addr: LLVMOrcTargetAddress) -> Option<LLVMOrcTargetAddress> {
        self.inner.table.write().unwrap().insert(mangled_symbol, addr)
    }
    
    // pub fn multi_insert_mangled(&self, )
    
    #[inline]
    pub fn get_symbol(&self, mangled_symbol: &MangledSymbol) -> Option<LLVMOrcTargetAddress> {
        self.inner.table.read().unwrap().get(mangled_symbol).cloned()
    }
}

#[derive(Debug)]
pub(crate) struct LocalSymbolTableInner {
    global_table: Option<GlobalSymbolTable>,
    local_table: HashMap<MangledSymbol, LLVMOrcTargetAddress>,
}

impl<'ctx> LocalSymbolTableInner {
    /// First searches the local table for the symbol, then if not found, searches the global table.
    /// Returns None if the symbol was not found in either table.
    pub(crate) fn get_symbol(&self, mangled_symbol: &MangledSymbol) -> Option<LLVMOrcTargetAddress> {
        self.local_table
            .get(mangled_symbol).cloned()
            .or_else(move || self.global_table.as_ref()?.get_symbol(mangled_symbol))
    }
}

// TODOC (ErisianArchitect): struct LocalSymbolTable
#[derive(Debug, Clone)]
pub(crate) struct LocalSymbolTable {
    // This doesn't need interior mutability, and in fact the LocalSymbolTable should be immutable, but this makes it
    // easy to get a mutable pointer (`*mut LocalSymbolTableInner`) safely.
    inner: Arc<LocalSymbolTableInner>,
}

// TODOC (ErisianArchitect): impl LocalSymbolTable
impl LocalSymbolTable {
    
    #[must_use]
    pub(crate) fn new(global_table: Option<GlobalSymbolTable>, local_table: HashMap<MangledSymbol, LLVMOrcTargetAddress>) -> Self {
        Self {
            inner: Arc::new(LocalSymbolTableInner {
                global_table,
                local_table,
            })
        }
    }
    
    #[must_use]
    #[inline]
    pub(crate) unsafe fn as_ptr(&self) -> *const LocalSymbolTableInner {
        Arc::as_ptr(&self.inner)
    }
}

// TODOC (ErisianArchitect): struct SymbolTable
#[derive(Debug)]
pub struct SymbolTable<'jit> {
    // It's safe for SymbolTable to have the JITStackRef because it is tied to the lifetime of the OrcEngine.
    pub(crate) jit_stack: LLVMOrcJITStackRef,
    pub(crate) symbols: HashMap<MangledSymbol, LLVMOrcTargetAddress>,
    _lifetime: PhantomData<&'jit ()>,
}

// TODOC (ErisianArchitect): impl SymbolTable
impl<'jit> SymbolTable<'jit> {
    #[must_use]
    #[inline]
    pub(crate) fn new(jit_stack: LLVMOrcJITStackRef) -> Self {
        Self {
            jit_stack,
            symbols: HashMap::new(),
            _lifetime: PhantomData,
        }
    }
    
    #[inline]
    pub fn register_mangled<F: UnsafeOrcFn>(&mut self, mangled_symbol: MangledSymbol, function: F) -> Option<LLVMOrcTargetAddress> {
        let addr: usize = unsafe { transmute_copy(&function) };
        self.symbols.insert(mangled_symbol, addr as LLVMOrcTargetAddress)
    }
    
    #[inline]
    pub fn register<F: UnsafeOrcFn>(&mut self, name: &str, function: F) -> Option<LLVMOrcTargetAddress> {
        let mangled_symbol = unsafe { mangle_symbol(self.jit_stack, name) };
        self.register_mangled(mangled_symbol, function)
    }
    
    #[must_use]
    #[inline]
    pub fn contains_mangled(&self, mangled_symbol: &MangledSymbol) -> bool {
        self.symbols.contains_key(mangled_symbol)
    }
    
    #[must_use]
    #[inline]
    pub fn contains(&self, name: &str) -> bool {
        let mangled_symbol = unsafe { mangle_symbol(self.jit_stack, name) };
        self.contains_mangled(&mangled_symbol)
    }
    
    #[must_use]
    #[inline]
    pub(crate) fn take_inner(self) -> HashMap<MangledSymbol, LLVMOrcTargetAddress> {
        self.symbols
    }
}

// pub type LLVMOrcSymbolResolverFn = Option<extern "C" fn(_: *const c_char, _: *mut c_void) -> u64>;
/// This function can be passed as LLVMOrcSymbolResolverFn in LLVMOrcAddEagerCompiledIR and LLVMOrcAddLazilyCompiledIR.
pub(crate) extern "C" fn orc_engine_symbol_resolver(mangled_cstr: *const c_char, context: *mut c_void) -> LLVMOrcTargetAddress {
    let sym_table_ptr: *const LocalSymbolTableInner = context.cast();
    if sym_table_ptr.is_null() {
        // This is an error, but we cannot panic here.
        return 0;
    }
    let locals = unsafe { sym_table_ptr.as_ref() }.unwrap();
    // Create a temporary MangledSymbol value based on the provided cstr. This MangledSymbol will be prevented from
    // dropping after the symbol is looked up.
    let temp_mangled_symbol = unsafe { MangledSymbol::from_mangled_cstr(mangled_cstr as _) };
    // returning 0 means the symbol was not found.
    let result = locals.get_symbol(&temp_mangled_symbol).unwrap_or(0);
    // destructure the MangledSymbol and Arc in order to forget about the inner value so that it is not double-freed.
    // the symbol resolution system owns the mangled string.
    let MangledSymbol { symbol } = temp_mangled_symbol;
    if let Some(inner) = Arc::into_inner(symbol) {
        std::mem::forget(inner);
    } else {
        eprintln!("Error: Somehow MangledSymbol was not exclusive during symbol resolution.");
    }
    result
}