use std::sync::LazyLock;

use llvm_sys::prelude::LLVMJITEventListenerRef;

#[cfg(any(target_os = "linux", unix))]
use llvm_sys::execution_engine::LLVMCreateGDBRegistrationListener;
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"))]
use llvm_sys::execution_engine::LLVMCreateIntelJITEventListener;
#[cfg(target_os = "linux")]
use llvm_sys::execution_engine::{
    LLVMCreateOProfileJITEventListener,
    LLVMCreatePerfJITEventListener,
};

// TODOC (ErisianArchitect): struct JitEventListener
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JitEventListener {
    pub(crate) raw: LLVMJITEventListenerRef,
}

thread_local! {
    #[cfg(any(target_os = "linux", unix))]
    static GDB_LISTENER: LazyLock<JitEventListener> = LazyLock::new(
        || {
            JitEventListener {
                raw: unsafe { LLVMCreateGDBRegistrationListener() }
            }
        }
    );
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"))]
    static INTEL_LISTENER: LazyLock<JitEventListener> = LazyLock::new(
        || {
            JitEventListener {
                raw: unsafe { LLVMCreateIntelJITEventListener() }
            }
        }
    );
    #[cfg(target_os = "linux")]
    static OPROFILE_LISTENER: LazyLock<JitEventListener> = LazyLock::new(
        || {
            JitEventListener {
                raw: unsafe { LLVMCreateOProfileJITEventListener() }
            }
        }
    );
    #[cfg(target_os = "linux")]
    static PERF_LISTENER: LazyLock<JitEventListener> = LazyLock::new(
        || {
            JitEventListener {
                raw: unsafe { LLVMCreatePerfJITEventListener() }
            }
        }
    );
}


// TODO (ErisianArchitect): impl JitEventListener
impl JitEventListener {
    #[must_use]
    #[inline]
    pub fn raw(&self) -> LLVMJITEventListenerRef {
        self.raw
    }
    
    /// Creates a GDB Registration Listener
    #[cfg(any(target_os = "linux", unix))]
    #[must_use]
    #[inline]
    pub fn gdb() -> Self {
        GDB_LISTENER.with(|inner| **inner)
    }

    /// Creates an Intel JIT Event Listener for the Intel VTune Amplifier.
    /// This should only be used on intel CPUs.
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "vtune"))]
    #[must_use]
    #[inline]
    pub fn intel() -> Self {
        INTEL_LISTENER.with(|inner| **inner)
    }

    #[cfg(target_os = "linux")]
    #[must_use]
    #[inline]
    pub fn oprofile() -> Self {
        OPROFILE_LISTENER.with(|inner| **inner)
    }

    #[cfg(target_os = "linux")]
    #[must_use]
    #[inline]
    pub fn perf() -> Self {
        PERF_LISTENER.with(|inner| **inner)
    }
}