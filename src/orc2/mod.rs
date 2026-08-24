mod dump_objects;
mod enums;
mod indirect_stubs_manager;
mod lljit;
mod target_machine_builder;
mod thread_safe_context;
mod thread_safe_module;

pub use dump_objects::*;
pub use enums::*;
pub use indirect_stubs_manager::*;
pub use target_machine_builder::*;
pub use thread_safe_context::*;
pub use thread_safe_module::*;

// LLVM Documentation for this API can be found here: [https://llvm.org/doxygen/group__LLVMCExecutionEngine.html]
// Look for the `Topics` section.
// [https://llvm.org/doxygen/group__LLVMCExecutionEngine.html]
// [https://llvm.org/doxygen/group__LLVMCExecutionEngineLLJIT.html]

/* ---| Completion Status:
[ ]: LLVMOrcLLJITBuilderRef
    [x]: LLVMOrcCreateLLJITBuilder
    [x]: LLVMOrcDisposeLLJITBuilder
    [x]: LLVMOrcCreateLLJIT
    [ ]: LLVMOrcLLJITBuilderSetObjectLinkingLayerCreator
[ ]: LLVMOrcLLJITRef
    [x]: LLVMOrcCreateLLJIT
    [x]: LLVMOrcDisposeLLJIT
    [ ]: LLVMOrcLLJITGetGlobalPrefix
    [ ]: LLVMOrcLLJITGetMainJITDylib
    [ ]: LLVMOrcLLJITEnableDebugSupport
    [ ]: LLVMOrcLLJITGetObjectLinkingLayer
    [ ]: LLVMOrcLLJITGetExecutionSession
    [ ]: LLVMOrcLLJITGetIRTransformLayer
    [ ]: LLVMOrcLLJITGetObjTransformLayer
    [x]: LLVMOrcLLJITGetTripleString
    [ ]: LLVMOrcLLJITGetDataLayoutStr
    [ ]: LLVMOrcLLJITAddObjectFile
    [ ]: LLVMOrcLLJITAddLLVMIRModule
    [ ]: LLVMOrcLLJITMangleAndIntern
    [ ]: LLVMOrcLLJITAddObjectFileWithRT
    [ ]: LLVMOrcLLJITAddLLVMIRModuleWithRT
    [ ]: LLVMOrcLLJITLookup
[ ]: LLVMOrcDefinitionGeneratorRef
    [ ]: LLVMOrcCreateCustomCAPIDefinitionGenerator
    [ ]: LLVMOrcDisposeDefinitionGenerator
[x]: LLVMOrcDumpObjectsRef
    [x]: LLVMOrcCreateDumpObjects
    [x]: LLVMOrcDisposeDumpObjects
    [x]: LLVMOrcDumpObjects_CallOperator
[ ]: LLVMOrcExecutionSessionRef
[ ]: LLVMOrcIRTransformLayerRef
    [ ]: LLVMOrcIRTransformLayerEmit
    [ ]: LLVMOrcIRTransformLayerSetTransform
[x]: LLVMOrcIndirectStubsManagerRef
    [x]: LLVMOrcCreateLocalIndirectStubsManager
    [x]: LLVMOrcDisposeIndirectStubsManager
[ ]: LLVMOrcJITDylibRef
    [ ]: LLVMOrcJITDylibClear
    [ ]: LLVMOrcJITDylibCreateResourceTracker
    [ ]: LLVMOrcJITDylibDefine
    [ ]: LLVMOrcJITDylibAddGenerator
[x]: LLVMOrcJITTargetMachineBuilderRef
    [x]: LLVMOrcJITTargetMachineBuilderCreateFromTargetMachine
    [x]: LLVMOrcDisposeJITTargetMachineBuilder
    [x]: LLVMOrcJITTargetMachineBuilderDetectHost
    [x]: LLVMOrcJITTargetMachineBuilderSetTargetTriple
    [x]: LLVMOrcJITTargetMachineBuilderGetTargetTriple
[ ]: LLVMOrcLazyCallThroughManagerRef
    [ ]: LLVMOrcDisposeLazyCallThroughManager
    [ ]: LLVMOrcCreateLocalLazyCallThroughManager
[ ]: LLVMOrcLookupStateRef
    [ ]: LLVMOrcLookupStateContinueLookup
[ ]: LLVMOrcMaterializationResponsibilityRef
    [ ]: LLVMOrcDisposeMaterializationResponsibility
    [ ]: LLVMOrcMaterializationResponsibilityGetTargetDylib
    [ ]: LLVMOrcMaterializationResponsibilityFailMaterialization
    [ ]: LLVMOrcMaterializationResponsibilityGetExecutionSession
    [ ]: LLVMOrcMaterializationResponsibilityGetInitializerSymbol
    [ ]: LLVMOrcMaterializationResponsibilityReplace
    [ ]: LLVMOrcMaterializationResponsibilityNotifyResolved
    [ ]: LLVMOrcMaterializationResponsibilityDefineMaterializing
    [ ]: LLVMOrcMaterializationResponsibilityGetSymbols
    [ ]: LLVMOrcMaterializationResponsibilityNotifyEmitted
    [ ]: LLVMOrcMaterializationResponsibilityGetRequestedSymbols
    [ ]: LLVMOrcMaterializationResponsibilityDelegate
[ ]: LLVMOrcMaterializationUnitRef
    [ ]: LLVMOrcCreateCustomMaterializationUnit
    [ ]: LLVMOrcLazyReexports
    [ ]: LLVMOrcAbsoluteSymbols
    [ ]: LLVMOrcMaterializationUnitMaterializeFunction
[ ]: LLVMOrcObjectLayerRef
    [ ]: LLVMOrcDisposeObjectLayer
    [ ]: LLVMOrcRTDyldObjectLinkingLayerRegisterJITEventListener
    [ ]: LLVMOrcObjectLayerEmit
    [ ]: LLVMOrcObjectLayerAddObjectFile
    [ ]: LLVMOrcObjectLayerAddObjectFileWithRT
    [ ]: LLVMOrcCreateStaticLibrarySearchGeneratorForPath
[ ]: LLVMOrcObjectLinkingLayerRef
[ ]: LLVMOrcObjectTransformLayerRef
    [ ]: LLVMOrcObjectTransformLayerSetTransform
[ ]: LLVMOrcResourceTrackerRef
[ ]: LLVMOrcSymbolStringPoolEntryRef
    [ ]: LLVMOrcRetainSymbolStringPoolEntry
    [ ]: LLVMOrcReleaseSymbolStringPoolEntry
    [ ]: LLVMOrcSymbolStringPoolEntryStr
    [ ]: LLVMOrcDisposeSymbols
[ ]: LLVMOrcSymbolStringPoolRef
    [ ]: LLVMOrcSymbolStringPoolClearDeadEntries
[x]: LLVMOrcThreadSafeContextRef
    [x]: LLVMOrcCreateNewThreadSafeContext
    [x]: LLVMOrcCreateNewThreadSafeContextFromLLVMContext
    [x]: LLVMOrcDisposeThreadSafeContext
    [x]: LLVMOrcCreateNewThreadSafeModule
[x]: LLVMOrcThreadSafeModuleRef
    [x]: LLVMOrcDisposeThreadSafeModule
    [x]: LLVMOrcThreadSafeModuleWithModuleDo
[x]: Enums
    [x]: LLVMJITSymbolGenericFlags
    [x]: LLVMOrcJITDylibLookupFlags
    [x]: LLVMOrcLookupKind
    [x]: LLVMOrcSymbolLookupFlags
[ ]: Callbacks
    [ ]: LLVMOrcCAPIDefinitionGeneratorTryToGenerateFunction
    [ ]: LLVMOrcErrorReporterFunction
    [ ]: LLVMOrcExecutionSessionLookupHandleResultFunction
    [x]: LLVMOrcGenericIRModuleOperationFunction
    [ ]: LLVMOrcIRTransformLayerTransformFunction
    [ ]: LLVMOrcMaterializationUnitDestroyFunction
    [ ]: LLVMOrcMaterializationUnitDiscardFunction
    [ ]: LLVMOrcMaterializationUnitMaterializeFunction
    [ ]: LLVMOrcObjectTransformLayerTransformFunction
*/

/* ---| NOTES:
Available on versions:
- llvm12-0
- llvm13-0
- llvm14-0
- llvm15-0
- llvm16-0
- llvm17-0
- llvm18-1
- llvm19-1
- llvm20-1
- llvm21-1
- llvm22-1
*/
