use inkwell::{orc::{error::OrcError, CompilationMode, OrcEngine}, targets::{CodeModel, RelocMode, Target, TargetMachine}};


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