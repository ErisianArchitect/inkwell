use std::mem::transmute_copy;

use llvm_sys::orc::LLVMOrcTargetAddress;

use crate::orc::orc_jit_fn::UnsafeOrcFn;



// TODOC (ErisianArchitect): struct FunctionAddress
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionAddress {
    pub(crate) address: LLVMOrcTargetAddress
}

// TODOC (ErisianArchitect): impl FunctionAddress
impl FunctionAddress {
    pub const NULL: Self = Self::null();
    #[must_use]
    #[inline]
    pub fn new<F: UnsafeOrcFn>(function: F) -> Self {
        let address: usize = unsafe { transmute_copy(&function) };
        unsafe { Self::from_raw(address as LLVMOrcTargetAddress) }
    }
    
    /// Unsafe fallback for functions that cannot be represented with `UnsafeOrcFn`.
    #[must_use]
    #[inline]
    pub const unsafe fn from_raw(address: LLVMOrcTargetAddress) -> Self {
        Self {
            address
        }
    }
    
    #[must_use]
    #[inline]
    pub const fn null() -> Self {
        Self { address: 0 }
    }
    
    #[must_use]
    #[inline]
    pub fn address(self) -> LLVMOrcTargetAddress {
        self.address
    }
}

// This macro is not strictly necessary, but it makes coercion easier and less verbose.
/// Utility macro to create a [FunctionAddress] with less verbosity. This handles the coercion for you.
/// # Example
/// ```rust, no_run
/// mod jit_functions {
///     unsafe extern "C" fn add(a: i32, b: i32) -> i32 {
///         a + b
///     }
/// 
///     unsafe extern "C" fn say_hello() {
///         println!("Hello, world!");
///     }
/// }
/// 
/// // in fn main()
/// 
/// let engine: OrcEngine = ...;
/// 
/// let add_addr0 = fn_addr!(jit_functions::add : (i32, i32) -> i32);
/// // optionally, you can include `fn`, `extern "C" fn`, or `unsafe extern "C" fn` before the parameter list:
/// let add_addr1 = fn_addr!(jit_functions::add : fn(i32, i32) -> i32);
/// let add_addr2 = fn_addr!(jit_functions::add : extern "C" fn(i32, i32) -> i32);
/// let add_addr3 = fn_addr!(jit_functions::add : unsafe extern "C" fn(i32, i32) -> i32);
/// // When the function has no arguments nor return type, you can exclude the signature.
/// let say_hello_addr = fn_addr!(jit_functions::say_hello);
/// ```
#[macro_export]
macro_rules! fn_addr {
    ( $function:path : $( $( $( unsafe )? extern "C" )? fn )? ($( $param_ty:ty ),*) $( -> $output_ty:ty )? ) => {
        $crate::orc::function_address::
            FunctionAddress::new::<unsafe extern "C" fn($( $param_ty ),*) $( -> $output_ty )?>(
                $function
            )
    };
    ($function:path) => {
        $crate::fn_addr!($function : ())
    }
}

pub use crate::fn_addr;