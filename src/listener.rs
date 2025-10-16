use llvm_sys::prelude::LLVMJITEventListenerRef;

/// [LLVMJITEventListenerRef] singleton wrapper.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JitEventListener {
    pub(crate) raw: LLVMJITEventListenerRef,
}

impl JitEventListener {
    /// The raw [LLVMJITEventListenerRef].
    #[must_use]
    #[inline]
    pub fn raw(&self) -> LLVMJITEventListenerRef {
        self.raw
    }
    
    /// Creates a GDB Registration Listener
    #[cfg(target_family = "unix")]
    #[must_use]
    #[inline]
    pub fn gdb() -> Self {
        JitEventListener {
            raw: unsafe { llvm_sys::execution_engine::LLVMCreateGDBRegistrationListener() }
        }
    }

    /// Creates an Intel JIT Event Listener for the Intel VTune Amplifier.
    /// This should only be used on intel CPUs or CPUs that support the Intel VTune Amplifier.
    /// The `vtune` feature must be enabled to use this listener.
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"))]
    #[must_use]
    #[inline]
    pub fn intel() -> Self {
        JitEventListener {
            raw: unsafe { llvm_sys::execution_engine::LLVMCreateIntelJITEventListener() }
        }
    }

    /// Creates an OProfile JIT Event Listener.
    #[cfg(target_os = "linux")]
    #[must_use]
    #[inline]
    pub fn oprofile() -> Self {
        JitEventListener {
            raw: unsafe { llvm_sys::execution_engine::LLVMCreateOProfileJITEventListener() }
        }
    }
    
    /// Creates a Perf JIT Event Listener.
    #[cfg(target_os = "linux")]
    #[must_use]
    #[inline]
    pub fn perf() -> Self {
        JitEventListener {
            raw: unsafe { llvm_sys::execution_engine::LLVMCreatePerfJITEventListener() }
        }
    }
}