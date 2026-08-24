
use ::core::{
    ffi::{
        c_int,
    },
};

bitflags::bitflags! {
    // TODO (ErisianArchitect): Documentation.
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct JITSymbolGenericFlags: c_int {
        const NONE = 0;
        const EXPORTED = 1;
        const WEAK = 2;
        const CALLABLE = 4;
        const MATERIALIZATION_SIDE_EFFECTS_ONLY = 8;
    }
}

// TODO (ErisianArchitect): Documentation.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JITDylibLookupFlags {
    ExportedSymbolsOnly = 0,
    AllSymbols = 1,
}

// TODO (ErisianArchitect): Documentation.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LookupKind {
    Static = 0,
    DlSym = 1,
}

// TODO (ErisianArchitect): Documentation.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolLookupFlags {
    RequiredSymbol = 0,
    WeaklyReferencedSymbol = 1,
}
