pub mod dump_objects;
pub mod indirect_stubs_manager;
pub mod lljit;
pub mod target_machine_builder;

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
[ ]: LLVMOrcDumpObjectsRef
    [x]: LLVMOrcCreateDumpObjects
    [x]: LLVMOrcDisposeDumpObjects
    [ ]: LLVMOrcDumpObjects_CallOperator
[ ]: LLVMOrcExecutionSessionRef
[ ]: LLVMOrcIRTransformLayerRef
    [ ]: LLVMOrcIRTransformLayerEmit
    [ ]: LLVMOrcIRTransformLayerSetTransform
[ ]: LLVMOrcIndirectStubsManagerRef
    [ ]: LLVMOrcCreateLocalIndirectStubsManager
    [ ]: LLVMOrcDisposeIndirectStubsManager
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
    [ ]: LLVMOrcCreateCustomMateerializationUnit
    [ ]: LLVMOrcLazyReexports
    [ ]: LLVMOrcAbsoluteSymbols
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
[ ]: LLVMOrcThreadSafeContextRef
    [ ]: LLVMOrcCreateNewThreadSafeContext
    [ ]: LLVMOrcCreateNewThreadSafeContextFromLLVMContext
    [ ]: LLVMOrcDisposeThreadSafeContext
    [ ]: LLVMOrcCreateNewThreadSafeModule
[ ]: LLVMOrcThreadSafeModuleRef
    [ ]: LLVMOrcDisposeThreadSafeModule
    [ ]: LLVMOrcThreadSafeModuleWithModuleDo
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
