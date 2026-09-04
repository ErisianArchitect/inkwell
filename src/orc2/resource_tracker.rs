
use ::core::{
    ptr::{
        NonNull,
    },
};

use ::llvm_sys::{
    orc2::{
        LLVMOrcResourceTrackerRef,
        LLVMOrcOpaqueResourceTracker,
    },
};

// TODO (ErisianArchitect): ResourceTracker documentation.
#[repr(transparent)]
#[derive(Debug)]
pub struct ResourceTracker {
    ptr: NonNull<LLVMOrcOpaqueResourceTracker>,
}

impl ResourceTracker {
}
