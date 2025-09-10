use std::{cell::{BorrowError, RefCell}, collections::HashMap, ffi::CString, marker::PhantomData, pin::Pin, ptr, rc::{Rc, Weak as WeakRc}};

use llvm_sys::orc::{LLVMOrcGetMangledSymbol, LLVMOrcJITStackRef};

use crate::{orc::{mangled_symbol::{mangle_symbol, MangledSymbol}, OrcEngine, OrcEngineInner}, support::to_c_str};

#[derive(Debug, Clone)]
struct GlobalSymbolTableRc {
    map: Pin<Rc<RefCell<HashMap<MangledSymbol, u64>>>>,
}

// TODOC (ErisianArchitect): struct GlobalSymbolTable
#[derive(Debug, Clone)]
pub struct GlobalSymbolTable<'ctx> {
    inner: GlobalSymbolTableRc,
    jit_stack: LLVMOrcJITStackRef,
    _lifetime: PhantomData<fn(&'ctx ())>,
}

// TODO (ErisianArchitect): `GlobalSymbolTable::new` - better error type
impl<'ctx> GlobalSymbolTable<'ctx> {
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
    
    // TODO (ErisianArchitect): `GlobalSymbolTable::new_with` - better error type
    pub(crate) fn new_with(jit_stack: LLVMOrcJITStackRef, symbol_table: HashMap<MangledSymbol, u64>) -> Self {
        Self {
            inner: GlobalSymbolTableRc {
                map: Rc::pin(RefCell::new(symbol_table)),
            },
            jit_stack,
            _lifetime: PhantomData,
        }
    }
    
    pub fn contains_mangled_symbol(&self, mangled_symbol: &MangledSymbol) -> bool {
        self.inner.map.borrow().contains_key(mangled_symbol)
    }
    
    pub fn insert_mangled(&self, mangled_symbol: MangledSymbol, addr: u64) -> Option<u64> {
        self.inner.map.borrow_mut().insert(mangled_symbol, addr)
    }
    
    pub fn remove_mangled(&self, mangled_symbol: &MangledSymbol) -> Option<u64> {
        self.inner.map.borrow_mut().remove(mangled_symbol)
    }
    
    pub fn contains_symbol(&self, symbol: &str) -> bool {
        let mangled = unsafe { mangle_symbol(self.jit_stack, symbol) };
        self.contains_mangled_symbol(&mangled)
    }
    
    pub fn insert(&self, symbol: &str, addr: u64) -> Option<u64> {
        let mangled = unsafe { mangle_symbol(self.jit_stack, symbol) };
        self.insert_mangled(mangled, addr)
    }
    
    pub fn remove(&self, symbol: &str) -> Option<u64> {
        let mangled = unsafe { mangle_symbol(self.jit_stack, symbol) };
        self.remove_mangled(&mangled)
    }
    
    pub fn clear(&self) {
        self.inner.map.borrow_mut().clear()
    }
    
    pub fn len(&self) -> usize {
        self.inner.map.borrow().len()
    }
    
    pub fn capacity(&self) -> usize {
        self.inner.map.borrow().capacity()
    }
    
    pub(crate) fn as_ptr(&self) -> *mut HashMap<MangledSymbol, u64> {
        self.inner.map.as_ptr()
    }
}

#[derive(Debug)]
struct LocalSymbolTableInner {
    owning_engine: super::OrcEngineRc,
    map: RefCell<HashMap<MangledSymbol, u64>>,
}

pub(crate) type LocalSymbolTableRc = Rc<LocalSymbolTableInner>;

#[derive(Debug, Clone)]
pub struct LocalSymbolTable {
    rc: LocalSymbolTableRc,
}

impl LocalSymbolTable {
    fn get_mangled_symbol(&self, key: &str) -> MangledSymbol {
        let key_c_str = to_c_str(key);
        let key_ptr = match key_c_str {
            std::borrow::Cow::Borrowed(inner) => inner.as_ptr(),
            std::borrow::Cow::Owned(inner) => inner.as_ptr(),
        };
        let mut symbol: *mut i8 = ptr::null_mut();
        unsafe {
            LLVMOrcGetMangledSymbol(self.rc.owning_engine.inner.jit_stack, &mut symbol, key_ptr);
        }
        unsafe { MangledSymbol::from_mangled_cstr(symbol) }
    }
    
    pub fn insert(&self, key: &str, addr: u64) -> Option<u64> {
        let key_c_str = to_c_str(key);
        let key_ptr = match key_c_str {
            std::borrow::Cow::Borrowed(inner) => inner.as_ptr(),
            std::borrow::Cow::Owned(inner) => inner.as_ptr(),
        };
        let mut symbol: *mut i8 = ptr::null_mut();
        unsafe {
            LLVMOrcGetMangledSymbol(self.rc.owning_engine.jit_stack, &mut symbol, key_ptr);
        }
        let mangled = MangledSymbol::from_mangled_cstr(symbol);
        self.rc.map.borrow_mut().insert(mangled, addr)
    }
    
    pub fn remove(&self, key: &str) -> Option<u64> {
        let key_c_str = to_c_str(key);
        let key_ptr = match key_c_str {
            std::borrow::Cow::Borrowed(inner) => inner.as_ptr(),
            std::borrow::Cow::Owned(inner) => inner.as_ptr(),
        };
        let mut symbol: *mut i8 = ptr::null_mut();
        unsafe {
            LLVMOrcGetMangledSymbol(self.rc.owning_engine.jit_stack, &mut symbol, key_ptr);
        }
        let mangled = MangledSymbol::from_mangled_cstr(symbol);
        self.rc.map.borrow_mut().remove(&mangled)
    }
    
    pub fn get(&self, key: &str) -> Option<u64> {
        self.rc.map.borrow().get(key).cloned()
    }
}