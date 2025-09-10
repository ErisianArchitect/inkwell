use std::{ffi::CStr, rc::Rc};

use libc::strlen;
use llvm_sys::error::{LLVMDisposeErrorMessage, LLVMGetErrorMessage, LLVMOpaqueError};

use crate::error::LLVMErrorString;

/// Handles an [LLVMOpaqueError] that was issued from LLVM.
pub(crate) fn handle_llvm_error_message(opaque: *mut LLVMOpaqueError) -> Result<(), LLVMErrorString> {
    if opaque.is_null() {
        Ok(())
    } else {
        Err(unsafe { LLVMErrorString::from_opaque(opaque) })
    }
}

// TODOC (ErisianArchitect): enum OrcError
#[derive(Debug, Clone, thiserror::Error)]
pub enum OrcError {
    #[error("Failed to create Orc JIT engine.")]
    CreateInstanceFailure,
    #[error("Failed to create eagerly compiled IR module.")]
    AddEagerlyCompiledIRFailure,
    #[error("Failed to create lazily compiled IR module.")]
    AddLazilyCompiledIRFailure,
    #[error("LLVM Error: {0}")]
    LLVMError(#[from] LLVMErrorString),
}