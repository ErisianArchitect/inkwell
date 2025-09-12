use std::{borrow::Cow, ffi::{CStr, CString}, rc::Rc};
use libc::{c_char, strlen};
use llvm_sys::orc::{LLVMOrcDisposeMangledSymbol, LLVMOrcGetMangledSymbol, LLVMOrcJITStackRef};

use crate::support::to_c_str;

// TODOC (ErisianArchitect): mangle_symbol()
pub(crate) unsafe fn mangle_symbol(jit_stack: LLVMOrcJITStackRef, name: &str) -> MangledSymbol {
    let name_c_str = to_c_str(name);
    let mut symbol: *mut i8 = std::ptr::null_mut();
    LLVMOrcGetMangledSymbol(jit_stack, &mut symbol, name_c_str.as_ptr());
    MangledSymbol::from_mangled_cstr(symbol)
}

pub(crate) struct MangledSymbolInner {
    c_str: *mut c_char,
    // len is a measure of the string length without the null terminator.
    // add 1 to the len to get the full length with null terminator.
    len: usize,
}

// TODOC (ErisianArchitect): struct MangledSymbol
#[derive(Clone)]
pub struct MangledSymbol {
    symbol: Rc<MangledSymbolInner>,
}

// TODOC (ErisianArchitect): impl MangledSymbol
impl MangledSymbol {
    #[must_use]
    #[inline]
    pub(crate) unsafe fn from_mangled_cstr(mangled_cstr: *mut c_char) -> Self {
        debug_assert!(!mangled_cstr.is_null(), "mangled_cstr must not be null.");
        // SAFETY: mangled_cstr is expected to be a value returned from `LLVMOrcGetMangledSymbol`, which is
        // a valid UTF-8 C string.
        let len = strlen(mangled_cstr);
        Self {
            symbol: Rc::new(MangledSymbolInner { c_str: mangled_cstr, len }),
        }
    }
    
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.symbol.len
    }
    
    #[must_use]
    #[inline]
    pub fn to_str(&self) -> &str {
        // SAFETY: symbol is valid UTF-8 string, and the len has already been calculated in `MangledSymbol::new`.
        let byte_slice = unsafe { std::slice::from_raw_parts(self.symbol.c_str as *const u8, self.symbol.len) };
        unsafe { str::from_utf8_unchecked(byte_slice) }
    }
    
    #[must_use]
    #[inline]
    pub fn to_cstr(&self) -> &CStr {
        // add 1 for the null byte at the end.
        let len = self.symbol.len + 1;
        let bytes = unsafe { std::slice::from_raw_parts(self.symbol.c_str as *mut u8, len) };
        unsafe { CStr::from_bytes_with_nul_unchecked(bytes) }
    }
}

impl std::borrow::Borrow<str> for MangledSymbol {
    #[inline]
    fn borrow(&self) -> &str {
        self.to_str()
    }
}

impl std::borrow::Borrow<CStr> for MangledSymbol {
    #[inline]
    fn borrow(&self) -> &CStr {
        self.to_cstr()
    }
}

impl AsRef<str> for MangledSymbol {
    #[inline]
    fn as_ref(&self) -> &str {
        self.to_str()
    }
}

impl AsRef<CStr> for MangledSymbol {
    #[inline]
    fn as_ref(&self) -> &CStr {
        self.to_cstr()
    }
}

impl From<MangledSymbol> for String {
    #[inline]
    fn from(value: MangledSymbol) -> Self {
        value.to_str().to_owned()
    }
}

impl From<MangledSymbol> for CString {
    #[inline]
    fn from(value: MangledSymbol) -> Self {
        value.to_cstr().to_owned()
    }
}

impl std::cmp::PartialEq<MangledSymbol> for MangledSymbol {
    #[inline]
    fn eq(&self, other: &MangledSymbol) -> bool {
        self.symbol.c_str == other.symbol.c_str || self.to_str() == other.to_str()
    }
    
    #[inline]
    fn ne(&self, other: &MangledSymbol) -> bool {
        self.symbol.c_str != other.symbol.c_str || self.to_str() != other.to_str()
    }
}

impl std::cmp::PartialEq<str> for MangledSymbol {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.to_str() == other
    }
    
    #[inline]
    fn ne(&self, other: &str) -> bool {
        self.to_str() != other
    }
}

impl std::cmp::PartialEq<String> for MangledSymbol {
    #[inline]
    fn eq(&self, other: &String) -> bool {
        self.to_str() == other
    }
    
    #[inline]
    fn ne(&self, other: &String) -> bool {
        self.to_str() != other
    }
}

impl std::cmp::Eq for MangledSymbol {}

impl std::hash::Hash for MangledSymbol {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_str().hash(state);
    }
}

impl std::fmt::Display for MangledSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl std::fmt::Debug for MangledSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_str())
    }
}

impl Drop for MangledSymbolInner {
    fn drop(&mut self) {
        unsafe { LLVMOrcDisposeMangledSymbol(self.c_str) };
    }
}