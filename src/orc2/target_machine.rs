
use ::core::{
    ptr::{
        NonNull,
    },
    mem::{
        ManuallyDrop,
    },
};

use ::llvm_sys::{
    orc2::{
        LLVMOrcJITTargetMachineBuilderCreateFromTargetMachine,
        LLVMOrcOpaqueJITTargetMachineBuilder,
        LLVMOrcJITTargetMachineBuilderRef,
        LLVMOrcDisposeJITTargetMachineBuilder,
    },
};

use crate::{
    targets::TargetMachine,
};


/// A [NonNull] variant that wraps [LLVMOrcOpaqueJITTargetMachineBuilder], which is the equivalent of a non-null
/// [LLVMOrcJITTargetMachineBuilderRef].
pub type JITTargetMachineBuilderNonNull = NonNull<LLVMOrcOpaqueJITTargetMachineBuilder>;

// [https://llvm.org/doxygen/classllvm_1_1orc_1_1JITTargetMachineBuilder.html]
/// A utility struct for constructing JIT Target Machines.
#[repr(transparent)]
#[derive(Debug)]
pub struct JITTargetMachineBuilder {
    ptr: JITTargetMachineBuilderNonNull,
}

impl JITTargetMachineBuilder {
    pub fn create_from_target_machine(target_machine: TargetMachine) -> Self {
        // This function takes ownership of the target machine.
        // [https://llvm.org/doxygen/group__LLVMCExecutionEngineORC.html#ga60a76da97b1229d5303eff475fb9a8e8]
        unsafe {
            let target_machine = ManuallyDrop::new(target_machine);
            let target_machine_ref = target_machine.as_mut_ptr();
            let ptr = LLVMOrcJITTargetMachineBuilderCreateFromTargetMachine(target_machine_ref);
            let Some(ptr) = NonNull::new(ptr) else {
                crate::support::panic_out_of_memory_error(
                    file!(),
                    line!(),
                    "Unable to create JITTargetMachineBuilder from TargetMachine.",
                );
            };
            Self {
                ptr,
            }
        }
    }
    
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcJITTargetMachineBuilderRef {
        self.ptr.as_ptr()
    }
}

impl Drop for JITTargetMachineBuilder {
    fn drop(&mut self) {
        unsafe {
            LLVMOrcDisposeJITTargetMachineBuilder(self.as_ptr());
        }
    }
}
