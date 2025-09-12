use std::{cell::{BorrowError, RefCell}, collections::HashMap, ffi::CString, marker::PhantomData, os::raw::c_void, pin::Pin, ptr, rc::{Rc, Weak as WeakRc}};

use libc::c_char;
use llvm_sys::orc::{LLVMOrcGetMangledSymbol, LLVMOrcJITStackRef};

use crate::{orc::{mangled_symbol::{mangle_symbol, MangledSymbol}, OrcEngine, OrcEngineInner}, support::to_c_str};

// TODO (ErisianArchitect): Create IntoSymbolTable trait and implement for some types.
//                          IntoSymbolTable should be used to create a HashMap<MangledSymbol, u64>.

#[derive(Debug)]
pub(crate) struct GlobalSymbolTableInner<'ctx> {
    pub(crate) map: RefCell<HashMap<MangledSymbol, u64>>,
    pub(crate) jit_stack: LLVMOrcJITStackRef,
    _lifetime: PhantomData<&'ctx ()>,
}

// TODOC (ErisianArchitect): struct GlobalSymbolTable
#[derive(Debug, Clone)]
pub struct GlobalSymbolTable<'ctx> {
    pub(crate) inner: Rc<GlobalSymbolTableInner<'ctx>>,
    _lifetime: PhantomData<&'ctx ()>,
}

// TODOC (ErisianArchitect): impl GlobalSymbolTable
impl<'ctx> GlobalSymbolTable<'ctx> {
    #[must_use]
    pub(crate) unsafe fn new(jit_stack: LLVMOrcJITStackRef, symbols: Option<&HashMap<String, u64>>) -> Self {
        Self::new_with(
            jit_stack,
            symbols
                .map(move |table| table
                    .iter()
                    .map(move |(name, &addr)| (
                        unsafe { mangle_symbol(jit_stack, name) },
                        addr,
                    ))
                    .collect()
                )
                .unwrap_or_else(HashMap::new)
        )
    }
    
    #[must_use]
    pub(crate) fn new_with(jit_stack: LLVMOrcJITStackRef, symbol_table: HashMap<MangledSymbol, u64>) -> Self {
        Self {
            inner: Rc::new(GlobalSymbolTableInner { 
                map: RefCell::new(symbol_table),
                jit_stack,
                _lifetime: PhantomData,
            }),
            _lifetime: PhantomData,
        }
    }
    
    #[must_use]
    #[inline]
    pub(crate) unsafe fn jit_stack(&self) -> LLVMOrcJITStackRef {
        self.inner.jit_stack
    }
    
    #[must_use]
    #[inline]
    pub fn contains_mangled(&self, mangled_symbol: &MangledSymbol) -> bool {
        self.inner.map.borrow().contains_key(mangled_symbol)
    }
    
    #[inline]
    pub fn insert_mangled(&self, mangled_symbol: MangledSymbol, addr: u64) -> Option<u64> {
        self.inner.map.borrow_mut().insert(mangled_symbol, addr)
    }
    
    #[inline]
    pub fn remove_mangled(&self, mangled_symbol: &MangledSymbol) -> Option<u64> {
        self.inner.map.borrow_mut().remove(mangled_symbol)
    }
    
    #[must_use]
    #[inline]
    pub fn contains(&self, symbol: &str) -> bool {
        let mangled_symbol = unsafe { mangle_symbol(self.inner.jit_stack, symbol) };
        self.contains_mangled(&mangled_symbol)
    }
    
    #[inline]
    pub fn insert(&self, symbol: &str, addr: u64) -> Option<u64> {
        let mangled_symbol = unsafe { mangle_symbol(self.inner.jit_stack, symbol) };
        self.insert_mangled(mangled_symbol, addr)
    }
    
    #[inline]
    pub fn remove(&self, symbol: &str) -> Option<u64> {
        let mangled_symbol = unsafe { mangle_symbol(self.inner.jit_stack, symbol) };
        self.remove_mangled(&mangled_symbol)
    }
    
    #[inline]
    pub fn get_symbol(&self, mangled_symbol: &MangledSymbol) -> Option<u64> {
        self.inner.map.borrow().get(mangled_symbol).cloned()
    }
    
    #[inline]
    pub fn get(&self, symbol: &str) -> Option<u64> {
        let mangled_symbol = unsafe { mangle_symbol(self.jit_stack(), symbol) };
        self.get_symbol(&mangled_symbol)
    }
    
    #[inline]
    pub fn clear(&self) {
        self.inner.map.borrow_mut().clear()
    }
    
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.map.borrow().len()
    }
    
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.map.borrow().capacity()
    }
}

#[derive(Debug)]
pub(crate) struct LocalSymbolTableInner<'ctx> {
    global_table: GlobalSymbolTable<'ctx>,
    local_table: HashMap<MangledSymbol, u64>,
    _lifetime: PhantomData<&'ctx ()>,
}

impl<'ctx> LocalSymbolTableInner<'ctx> {
    /// First searches the local table for the symbol, then if not found, searches the global table.
    /// Returns None if the symbol was not found in either table.
    pub(crate) fn get_symbol(&self, mangled_symbol: &MangledSymbol) -> Option<u64> {
        self.local_table
            .get(mangled_symbol)
            .cloned()
            .or_else(move || self.global_table.get_symbol(mangled_symbol))
    }
}

// TODOC (ErisianArchitect): struct LocalSymbolTable
#[derive(Debug, Clone)]
pub(crate) struct LocalSymbolTable<'ctx> {
    // This doesn't need interior mutability, and in fact the LocalSymbolTable should be immutable, but this makes it
    // easy to get a mutable pointer (`*mut LocalSymbolTableInner`) safely.
    inner: Rc<RefCell<LocalSymbolTableInner<'ctx>>>,
}

// TODOC (ErisianArchitect): impl LocalSymbolTable
impl<'ctx> LocalSymbolTable<'ctx> {
    #[must_use]
    pub(crate) fn new(global_table: GlobalSymbolTable<'ctx>, local_table: Option<&HashMap<String, u64>>) -> Self {
        let jit_stack = unsafe { global_table.jit_stack() };
        Self::new_with(
            global_table,
            local_table.map(move |table| {
                table.iter().map(move |(name, &addr)| (
                    unsafe { mangle_symbol(jit_stack, name) },
                    addr,
                )).collect()
            }).unwrap_or_else(HashMap::new),
        )
    }
    
    #[must_use]
    pub(crate) fn new_with(global_table: GlobalSymbolTable<'ctx>, local_table: HashMap<MangledSymbol, u64>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(LocalSymbolTableInner {
                global_table,
                local_table: local_table,
                _lifetime: PhantomData,
            }))
        }
    }
    
    #[must_use]
    #[inline]
    pub(crate) unsafe fn as_ptr(&self) -> *mut LocalSymbolTableInner<'ctx> {
        self.inner.as_ptr()
    }
}

#[derive(Debug)]
pub struct SymbolTable<'ctx> {
    // It's safe for SymbolTable to have the JITStackRef because it is tied to the lifetime of the OrcEngine.
    jit_stack: LLVMOrcJITStackRef,
    symbols: HashMap<MangledSymbol, u64>,
    _lifetime: PhantomData<&'ctx ()>,
}

// pub type LLVMOrcSymbolResolverFn = Option<extern "C" fn(_: *const c_char, _: *mut c_void) -> u64>;
/// This function can be passed as LLVMOrcSymbolResolverFn in LLVMOrcAddEagerCompiledIR and LLVMOrcAddLazilyCompiledIR.
pub(crate) extern "C" fn module_symbol_resolver(mangled_cstr: *const c_char, context: *mut c_void) -> u64 {
    let sym_table_ptr: *mut LocalSymbolTableInner<'static> = context.cast();
    if sym_table_ptr.is_null() {
        // This is an error, but we cannot panic here.
        return 0;
    }
    let locals = unsafe { sym_table_ptr.as_ref() }.unwrap();
    // must be ManuallyDrop since the mangled string is managed by LLVM.
    let mangled_symbol = std::mem::ManuallyDrop::new(unsafe { MangledSymbol::from_mangled_cstr(mangled_cstr as _) });
    // returning 0 means the symbol was not found.
    locals.get_symbol(&mangled_symbol).unwrap_or(0)
}