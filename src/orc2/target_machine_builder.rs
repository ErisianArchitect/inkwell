
use ::core::{
    ptr::{
        self,
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
        LLVMOrcJITTargetMachineBuilderDetectHost,
        LLVMOrcJITTargetMachineBuilderSetTargetTriple,
        LLVMOrcJITTargetMachineBuilderGetTargetTriple,
    },
};

use crate::{
    targets::{TargetMachine, TargetTriple},
    error::{LLVMError},
    support::{LLVMString},
};


// [https://llvm.org/doxygen/classllvm_1_1orc_1_1JITTargetMachineBuilder.html]
/// A utility struct for constructing JIT Target Machines.
#[repr(transparent)]
#[derive(Debug)]
pub struct JITTargetMachineBuilder {
    ptr: NonNull<LLVMOrcOpaqueJITTargetMachineBuilder>,
}
const _: () = crate::support::assert_niche::<JITTargetMachineBuilder>();

impl JITTargetMachineBuilder {
    /// Create a [JITTargetMachineBuilder] from a [TargetMachine]. This will take ownership of the [TargetMachine].
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

    /// Returns the inner [LLVMOrcJITTargetMachineBuilderRef].
    ///
    /// NOTE: [JITTargetMachineBuilder] is a transparent wrapper around this pointer.
    #[must_use]
    #[inline(always)]
    pub fn as_ptr(&self) -> LLVMOrcJITTargetMachineBuilderRef {
        self.ptr.as_ptr()
    }

    // [https://llvm.org/doxygen/classllvm_1_1orc_1_1JITTargetMachineBuilder.html#aa67d14db111b10a6a09cb70fa5f4e084]
    /// Attempt to create a [JITTargetMachineBuilder] for the host system.
    pub fn detect_host() -> Result<Self, LLVMError> {
        let mut builder = ptr::null_mut();
        unsafe {
            let result = LLVMError::from_error_ref(LLVMOrcJITTargetMachineBuilderDetectHost(&mut builder));
            if let Some(error) = result {
                return Err(error);
            }
            let Some(ptr) = NonNull::new(builder) else {
                crate::support::panic_out_of_memory_error(file!(), line!(), "Attempt to detect host failed.");
            };
            Ok(Self {
                ptr,
            })
        }
    }

    /// Sets the [TargetTriple] of the [JITTargetMachineBuilder].
    pub fn set_target_triple(&mut self, triple: &TargetTriple) {
        // SetTargetTriple does not take ownership of the `triple` string.
        // [https://llvm.org/doxygen/OrcV2CBindings_8cpp_source.html] (line 809)
        // [https://llvm.org/doxygen/Triple_8h_source.html] (line 462)
        let triple_t_cstr = triple.as_str();
        unsafe {
            LLVMOrcJITTargetMachineBuilderSetTargetTriple(self.as_ptr(), triple_t_cstr.as_ptr());
        }
    }

    /// Get the [TargetTriple] for this [JITTargetMachineBuilder].
    pub fn get_target_triple(&self) -> TargetTriple {
        // LLMVOrcJITTargetMachineBuilderGetTargetTriple will create a new TargetTriple string.
        // [https://llvm.org/doxygen/OrcV2CBindings_8cpp_source.html] (line 801)
        unsafe {
            let ptr = LLVMOrcJITTargetMachineBuilderGetTargetTriple(self.as_ptr());
            let Some(ptr) = NonNull::new(ptr) else {
                crate::support::panic_out_of_memory_error(file!(), line!(), "Unable to get TargetTriple.");
            };
            TargetTriple {
                triple: LLVMString { ptr },
            }
        }
    }
}

impl Drop for JITTargetMachineBuilder {
    fn drop(&mut self) {
        unsafe {
            LLVMOrcDisposeJITTargetMachineBuilder(self.as_ptr());
        }
    }
}
