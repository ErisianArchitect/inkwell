use std::mem::transmute_copy;

use llvm_sys::orc::LLVMOrcTargetAddress;

use crate::orc::orc_jit_fn::UnsafeOrcFn;

// NOTE: FunctionAddress must be repr(transparent) to ensure that it is interchangeable with LLVMOrcTargetAddress.
/// A safe function address wrapper. [FunctionAddress] can easily be created using the `fn_addr!` macro.
/// 
/// # Example
/// ```
/// use inkwell::{fn_addr, orc::function_address::FunctionAddress};
/// 
/// pub mod functions {
///     pub unsafe extern "C" fn less_or_equal(a: i32, b: i32) -> bool {
///         a <= b
///     }
/// }
/// // ...
/// let lte = fn_addr!(functions::less_or_equal : (i32, i32) -> bool);
/// // or
/// let lte = FunctionAddress::new::<unsafe extern "C" fn(i32, i32) -> bool>(functions::less_or_equal);
/// ```
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FunctionAddress(pub(crate) LLVMOrcTargetAddress);

// SAFETY: LLVMOrcTargetAddress should just be a primitive type, and should be safe to send across thread boundaries.
//         These traits might be auto-implemented, but I figured it would be a good idea to force their implementation
//         just in case.
unsafe impl Send for FunctionAddress {}
unsafe impl Sync for FunctionAddress {}

// TODOC (ErisianArchitect): impl FunctionAddress
impl FunctionAddress {
    /// Null [FunctionAddress] (address of zero).
    pub const NULL: Self = Self(0);
    
    // NOTE: Either NULL or fn null() can be removed, but having them both gives users options for when they prefer a
    // function over a const. Everyone hates CAPS LOCK. Also, it means that you can provide `FunctionAddress::null` as
    // input to something that expects a function that returns FunctionAddress.
    /// Creates a null [FunctionAddress] (address of zero).
    #[must_use]
    #[inline(always)]
    pub const fn null() -> Self {
        Self::NULL
    }
    
    /// Unsafe fallback for functions that cannot be represented with `UnsafeOrcFn`.
    #[must_use]
    #[inline(always)]
    pub unsafe fn from_raw(address: LLVMOrcTargetAddress) -> Self {
        Self(address)
    }
    
    #[must_use]
    #[inline]
    pub fn new<F: UnsafeOrcFn>(function: F) -> Self {
        // SAFETY: UnsafeOrcFn is only implemented for function pointers, so transmuting to `usize` is a valid
        //         operation.
        let address: usize = unsafe { transmute_copy(&function) };
        unsafe { Self::from_raw(address as _) }
    }
    
    /// Gets the raw [LLVMOrcTargetAddress] that this [FunctionAddress] wraps.
    #[must_use]
    #[inline(always)]
    pub fn raw(self) -> LLVMOrcTargetAddress {
        self.0
    }
}

/// Utility macro to create a [FunctionAddress] with less verbosity. This handles the coercion for you.
/// 
/// # Syntax
/// `fn_addr!($function:path : ( $( $param_type:ty ),* ) $( -> $return_type:ty )?)`
/// # Example
/// ```rust, no_run
/// use inkwell::orc::{OrcEngine, function_address::FunctionAddress};
/// use inkwell::fn_addr;
/// pub mod jit_functions {
///     pub unsafe extern "C" fn add(a: i32, b: i32) -> i32 {
///         a + b
///     }
/// 
///     pub unsafe extern "C" fn say_hello() {
///         println!("Hello, world!");
///     }
/// }
/// 
/// // in fn main()
/// 
/// let engine: OrcEngine = OrcEngine::new_default().expect("Failed to create OrcEngine.");
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