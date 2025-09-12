use std::{ffi::{CStr, NulError}, rc::Rc};

use libc::strlen;
use llvm_sys::error::{LLVMDisposeErrorMessage, LLVMGetErrorMessage, LLVMOpaqueError};

use crate::{error::LLVMErrorString, support::LLVMString};

/// Handles an [LLVMOpaqueError] that was issued from LLVM.
pub(crate) fn handle_llvm_error_message(opaque: *mut LLVMOpaqueError) -> Result<(), LLVMErrorString> {
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
    #[error("Failed to create lazily compiled IR module.")]
    AddLazilyCompiledIRFailure(LLVMErrorString),
    #[error("Failed to add object file.")]
    AddObjectFileFailure(LLVMErrorString),
    #[error("Failed to lookup symbol address: {0}")]
    SymbolAddressLookupFailure(LLVMErrorString),
    #[error("The module was already owned by an execution engine.")]
    ModuleOwnedByExecutionEngine,
    #[error("LLVM Error: {0}")]
    LLVMError(#[from] LLVMErrorString),
    #[error("LLVM: {0}")]
    LLVMString(#[from] LLVMString),
    #[error("NulError: {0}")]
    NulError(#[from] NulError),
}