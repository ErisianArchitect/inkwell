use std::ffi::NulError;

use llvm_sys::error::LLVMOpaqueError;

use crate::{error::LLVMErrorString, orc::mangled_symbol::MangledSymbol, support::LLVMString};

/// Handles an [LLVMOpaqueError] that was issued from LLVM.
pub fn handle_llvm_error_message(opaque: *mut LLVMOpaqueError) -> Result<(), LLVMErrorString> {
    if opaque.is_null() {
        Ok(())
    } else {
        Err(unsafe { LLVMErrorString::from_opaque(opaque) })
    }
}

// TODOC (ErisianArchitect): enum OrcError
#[derive(Debug, thiserror::Error)]
pub enum OrcError {
    #[error("Failed to create Orc JIT engine.")]
    CreateInstanceFailure,
    #[error("Failed to create eagerly compiled IR module: {0}")]
    AddEagerlyCompiledIRFailure(LLVMErrorString),
    #[error("Failed to create lazily compiled IR module: {0}")]
    AddLazilyCompiledIRFailure(LLVMErrorString),
    #[error("Failed to add object file.")]
    AddObjectFileFailure(LLVMErrorString),
    #[error("Failed to remove module.")]
    RemoveModuleFailure(LLVMErrorString),
    #[error("Failed to lookup symbol address: {0}")]
    SymbolAddressLookupFailure(LLVMErrorString),
    #[error("The given module name has already been used: {0:?}")]
    RepeatModuleName(Box<str>),
    #[error("The module was already owned by an execution engine.")]
    ModuleOwnedByExecutionEngine,
    #[error("The module was not found: {0:?}")]
    ModuleNotFound(Box<str>),
    #[error("A function by that mangled name has already been registered: {0:?}")]
    MangledFunctionAlreadyRegistered(MangledSymbol),
    #[error("A function by that name has already been registered: {0:?}")]
    FunctionAlreadyRegistered(Box<str>),
    #[error("Symbol was not found: {0:?}")]
    SymbolNotFound(Box<str>),
    #[error("Mangled Function was not found: {0:?}")]
    MangledSymbolNotFound(MangledSymbol),
    #[error("LLVM Error: {0}")]
    LLVMError(#[from] LLVMErrorString),
    #[error("LLVM: {0}")]
    LLVMString(#[from] LLVMString),
    #[error("NulError: {0}")]
    NulError(#[from] NulError),
}