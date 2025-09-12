use std::marker::PhantomData;


mod private {
    pub trait SealedUnsafeOrcJitFnPtr: Copy {}
}

pub trait UnsafeOrcJitFnPtr: private::SealedUnsafeOrcJitFnPtr {}

#[derive(Debug, Clone)]
pub struct OrcJitFunction<'ctx, F> {
    inner: F,
    _phantom: PhantomData<&'ctx ()>,
}

impl<'ctx, F> OrcJitFunction<'ctx, F> {
    #[must_use]
    #[inline]
    pub(crate) const fn new(function: F) -> Self {
        Self {
            inner: function,
            _phantom: PhantomData,
        }
    }
}

macro_rules! impl_unsafe_fn {
    (@recurse $first:ident $( , $rest:ident )*) => {
        impl_unsafe_fn!($( $rest ),*);
    };

    (@recurse) => {};
    
    ($( $param:ident ),*) => {
        impl<Output, $( $param ),*> private::SealedUnsafeOrcJitFnPtr for unsafe extern "C" fn($( $param ),*) -> Output {}
        impl<Output, $( $param ),*> UnsafeOrcJitFnPtr for unsafe extern "C" fn($( $param ),*) -> Output {}

        impl<Output, $( $param ),*> OrcJitFunction<'_, unsafe extern "C" fn($( $param ),*) -> Output> {
            /// This method allows you to call the underlying function while making
            /// sure that the backing storage is not dropped too early and
            /// preserves the `unsafe` marker for any calls.
            #[allow(non_snake_case)]
            #[inline(always)]
            pub unsafe fn call(&self, $( $param: $param ),*) -> Output {
                unsafe { (self.inner)($( $param ),*) }
            }
        }

        impl_unsafe_fn!(@recurse $( $param ),*);
    };
}

impl_unsafe_fn!(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16, T17, T18, T19, T20, T21, T22, T23, T24, T25, T26, T27, T28, T29, T30, T31);

#[macro_export]
macro_rules! orc_jit_fn_ty {
    (fn($($param:ty),*$(,)?)$( -> $result:ty)?) => {
        $crate::orc::orc_jit_fn::OrcJitFunction::<unsafe extern "C" fn($($param),*) $( -> $result )?>
    };
}