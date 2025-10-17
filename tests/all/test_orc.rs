use inkwell::{context::Context, module::Linkage, orc::{error::OrcError, CompilationMode, OrcEngine}, orc_fn, targets::{CodeModel, RelocMode, Target, TargetMachine}};


#[test]
fn test_create_orc_engine() -> Result<(), OrcError> {
    inkwell::targets::Target::initialize_native(&inkwell::targets::InitializationConfig::default())
        .expect("Failed to initialize native target");
    let triple = TargetMachine::get_default_triple();
    let target = Target::from_triple(&triple)?;
    let target_machine = target.create_target_machine(
        &triple,
        TargetMachine::get_host_cpu_name().to_str().unwrap(),
        TargetMachine::get_host_cpu_features().to_str().unwrap(),
        inkwell::OptimizationLevel::Default,
        RelocMode::Default,
        CodeModel::Default,
    ).ok_or_else(|| OrcError::CreateTargetMachineFailure)?;
    
    let engine = OrcEngine::with_target_machine(target_machine)?;
    
    let engine = OrcEngine::new(
        inkwell::OptimizationLevel::Default,
        RelocMode::Default,
        CodeModel::Default,
        None,
    )?;
    
    let engine = OrcEngine::new_default()?;
    use inkwell::context::Context;
    let context = Context::create();
    let module = context.create_module("main");
    
    assert!(engine.add_module(
        "main",
        module,
        &context,
        CompilationMode::Lazy,
        None,
    ).is_ok());
    Ok(())
}

#[test]
pub fn test_add_module() -> Result<(), inkwell::Error> {
    inkwell::targets::Target::initialize_native(&inkwell::targets::InitializationConfig::default())
        .expect("Failed to initialize native target");
    let context = Context::create();
    let module = context.create_module("main");
    let builder = context.create_builder();
    
    let i32_t = context.i32_type();
    
    let foo_fn_ty = i32_t.fn_type(&[i32_t.into(), i32_t.into()], false);
    let foo_fn = module.add_function("foo", foo_fn_ty, Some(Linkage::External));
    let entry = context.append_basic_block(foo_fn, "entry");
    
    builder.position_at_end(entry);
    
    let lhs = foo_fn.get_nth_param(0).expect("Could not get first argument").into_int_value();
    let rhs = foo_fn.get_nth_param(1).expect("Could not get second argument").into_int_value();
    
    let add_result = builder.build_int_add(lhs, rhs, "add_result")?;
    
    builder.build_return(Some(&add_result))?;
    
    module.verify().map_err(|err| inkwell::Error::OrcError(OrcError::LLVMString(err)))?;
    
    macro_rules! test_with_engine {
        ($orc_engine:expr) => {
            {
                let engine = $orc_engine;
                let module = module.clone();
                
                engine.add_module(
                    "main",
                    module,
                    &context,
                    CompilationMode::Lazy,
                    None,
                )?;
                
                let foo: orc_fn!(fn(i32, i32) -> i32) = unsafe { engine.get_function("foo")? };
                
                let foo_result = unsafe { foo.call(3, 5) };
                assert_eq!(foo_result, 3 + 5);
                
                let foo_result = unsafe { foo.call(7, 13) };
                assert_eq!(foo_result, 7 + 13);
            }
        };
    }
    macro_rules! test_with_optimization_level {
        ($opt_level:ident) => {
            test_with_engine!(OrcEngine::with_optimization_level(inkwell::OptimizationLevel::$opt_level)?);
        };
    }
    test_with_engine!(OrcEngine::new_default()?);
    test_with_optimization_level!(Aggressive);
    test_with_optimization_level!(Default);
    test_with_optimization_level!(Less);
    test_with_optimization_level!(None);
    
    Ok(())
}