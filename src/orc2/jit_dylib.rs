
use ::core::{
    ptr::{
        self,
        NonNull,
    },
    marker::{
        PhantomData,
    },
};

use ::llvm_sys::{
    orc2::{
        LLVMOrcOpaqueJITDylib,
        LLVMOrcJITDylibRef,
    },
};

use crate::{
    orc2::{
        lljit::LLJIT,
    },
};

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct JITDylibRef<'lljit> {
    pub(crate) ptr: NonNull<LLVMOrcOpaqueJITDylib>,
    // JITDylib is owned by LLJIT
    // [https://llvm.org/docs/doxygen/llvm-c_2LLJIT_8h_source.html#l00144]
    pub(crate) _phantom: PhantomData<(&'lljit LLJIT,)>
}
