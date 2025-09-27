
#[test]
fn test_jit_event_listener_singleton() {
    use inkwell::llvm_sys;
    use llvm_sys::prelude::*;
    use std::sync::{Arc, atomic::{AtomicPtr, Ordering}};
    fn assert_same_listener(create_listener: unsafe extern "C" fn() -> LLVMJITEventListenerRef) -> bool {
        let listener_ref1 = Arc::new(AtomicPtr::new(std::ptr::null_mut()));
        let listener_ref2 = Arc::new(AtomicPtr::new(std::ptr::null_mut()));
        {
            let listener_ref1 = Arc::clone(&listener_ref1);
            let thread1 = std::thread::spawn(move || {
                listener_ref1.store(unsafe { create_listener() }, Ordering::Release);
            });
            thread1.join();
        }
        {
            let listener_ref2 = Arc::clone(&listener_ref2);
            let thread2 = std::thread::spawn(move || {
                listener_ref2.store(unsafe { create_listener() }, Ordering::Release);
            });
            thread2.join();
        }
        let listener1 = listener_ref1.load(Ordering::Acquire);
        let listener2 = listener_ref2.load(Ordering::Acquire);
        listener1 == listener2
    }
    macro_rules! assert_eq_listener {
        (
            $(
                // In the future, an attributes matcher can be added. I left that code commented out as an example.
                // $(
                //     #[$attr:meta]
                // )*
                $listener_fn:path,
            )+
        ) => {
            $(
                // $(
                //     #[$attr]
                // )*
                assert!(
                    assert_same_listener(
                        $listener_fn
                    ),
                    "{} did not produce the same LLVMJITEventListenerRef on both threads.",
                    stringify!($listener_fn),
                );
            )*
        };
    }
    assert_eq_listener!(
        llvm_sys::execution_engine::LLVMCreateGDBRegistrationListener,
        llvm_sys::execution_engine::LLVMCreateIntelJITEventListener,
        llvm_sys::execution_engine::LLVMCreateOProfileJITEventListener,
        llvm_sys::execution_engine::LLVMCreatePerfJITEventListener,
    );
    println!("Finished.");
}