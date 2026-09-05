mod dump_objects;
mod enums;
mod indirect_stubs_manager;
mod jit_dylib;
mod object_layer;
mod resource_tracker;
mod target_machine_builder;
mod thread_safe_context;
mod thread_safe_module;

pub mod lljit;

pub use dump_objects::*;
pub use enums::*;
pub use indirect_stubs_manager::*;
pub use jit_dylib::*;
pub use object_layer::*;
pub use resource_tracker::*;
pub use target_machine_builder::*;
pub use thread_safe_context::*;
pub use thread_safe_module::*;

// ORC Design and Implementation:
// [https://llvm.org/docs/ORCv2.html]
// LLVM Documentation for this API can be found here:
// [https://llvm.org/doxygen/group__LLVMCExecutionEngine.html]
// --: Look for the `Topics` section.
//     [https://llvm.org/doxygen/group__LLVMCExecutionEngine.html]
//     [https://llvm.org/doxygen/group__LLVMCExecutionEngineLLJIT.html]

/* ---| Completion Status:
================================================================
[ ]: LLVMOrcLLJITBuilderRef
    [x]: LLVMOrcCreateLLJITBuilder
    [x]: LLVMOrcDisposeLLJITBuilder
    [x]: LLVMOrcCreateLLJIT
    [ ]: LLVMOrcLLJITBuilderSetObjectLinkingLayerCreator
[ ]: LLVMOrcLLJITRef
    [x]: LLVMOrcCreateLLJIT
    [x]: LLVMOrcDisposeLLJIT
    [x]: LLVMOrcLLJITGetGlobalPrefix
    [x]: LLVMOrcLLJITGetMainJITDylib
    [x]: LLVMOrcLLJITEnableDebugSupport
    [x]: LLVMOrcLLJITGetObjLinkingLayer
    [ ]: LLVMOrcLLJITGetExecutionSession
    [ ]: LLVMOrcLLJITGetIRTransformLayer
    [ ]: LLVMOrcLLJITGetObjTransformLayer
    [x]: LLVMOrcLLJITGetTripleString
    [x]: LLVMOrcLLJITGetDataLayoutStr
    [ ]: LLVMOrcLLJITAddObjectFile
    [ ]: LLVMOrcLLJITAddLLVMIRModule
    [ ]: LLVMOrcLLJITMangleAndIntern
    [x]: LLVMOrcLLJITAddObjectFileWithRT
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
    [x]: LLVMOrcJITDylibClear
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
[x]: LLVMOrcResourceTrackerRef
    [x]: LLVMOrcResourceTrackerRemove
    [x]: LLVMOrcReleaseResourceTracker
    [x]: LLVMOrcResourceTrackerTransferTo
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
================================================================


======== Full Checklist: ========
[ ]: llvm_sys::orc2::LLVMJITCSymbolMapPair
[ ]: llvm_sys::orc2::LLVMJITEvaluatedSymbol
[ ]: llvm_sys::orc2::LLVMJITSymbolFlags
[x]: llvm_sys::orc2::LLVMJITSymbolGenericFlags
[ ]: llvm_sys::orc2::LLVMJITSymbolTargetFlags
[ ]: llvm_sys::orc2::LLVMJITTargetSymbolFlags
[ ]: llvm_sys::orc2::LLVMOrcAbsoluteSymbols
[ ]: llvm_sys::orc2::LLVMOrcCAPIDefinitionGeneratorTryToGenerateFunction
[ ]: llvm_sys::orc2::LLVMOrcCDependenceMapPair
[ ]: llvm_sys::orc2::LLVMOrcCDependenceMapPairs
[ ]: llvm_sys::orc2::LLVMOrcCJITDylibSearchOrder
[ ]: llvm_sys::orc2::LLVMOrcCJITDylibSearchOrderElement
[ ]: llvm_sys::orc2::LLVMOrcCLookupSet
[ ]: llvm_sys::orc2::LLVMOrcCLookupSetElement
[ ]: llvm_sys::orc2::LLVMOrcCSymbolAliasMapEntry
[ ]: llvm_sys::orc2::LLVMOrcCSymbolAliasMapPair
[ ]: llvm_sys::orc2::LLVMOrcCSymbolAliasMapPairs
[ ]: llvm_sys::orc2::LLVMOrcCSymbolDependenceGroup
[ ]: llvm_sys::orc2::LLVMOrcCSymbolFlagsMapPair
[ ]: llvm_sys::orc2::LLVMOrcCSymbolFlagsMapPairs
[ ]: llvm_sys::orc2::LLVMOrcCSymbolMapPair
[ ]: llvm_sys::orc2::LLVMOrcCSymbolMapPairs
[ ]: llvm_sys::orc2::LLVMOrcCSymbolsList
[ ]: llvm_sys::orc2::LLVMOrcCreateCustomCAPIDefinitionGenerator
[ ]: llvm_sys::orc2::LLVMOrcCreateCustomMaterializationUnit
[x]: llvm_sys::orc2::LLVMOrcCreateDumpObjects
[ ]: llvm_sys::orc2::LLVMOrcCreateDynamicLibrarySearchGeneratorForPath
[ ]: llvm_sys::orc2::LLVMOrcCreateDynamicLibrarySearchGeneratorForProcess
[x]: llvm_sys::orc2::LLVMOrcCreateLocalIndirectStubsManager
[ ]: llvm_sys::orc2::LLVMOrcCreateLocalLazyCallThroughManager
[x]: llvm_sys::orc2::LLVMOrcCreateNewThreadSafeContext
[x]: llvm_sys::orc2::LLVMOrcCreateNewThreadSafeModule
[ ]: llvm_sys::orc2::LLVMOrcCreateStaticLibrarySearchGeneratorForPath
[ ]: llvm_sys::orc2::LLVMOrcDefinitionGeneratorRef
[ ]: llvm_sys::orc2::LLVMOrcDisposeCAPIDefinitionGeneratorFunction
[ ]: llvm_sys::orc2::LLVMOrcDisposeCSymbolFlagsMap
[ ]: llvm_sys::orc2::LLVMOrcDisposeDefinitionGenerator
[x]: llvm_sys::orc2::LLVMOrcDisposeDumpObjects
[x]: llvm_sys::orc2::LLVMOrcDisposeIndirectStubsManager
[x]: llvm_sys::orc2::LLVMOrcDisposeJITTargetMachineBuilder
[ ]: llvm_sys::orc2::LLVMOrcDisposeLazyCallThroughManager
[ ]: llvm_sys::orc2::LLVMOrcDisposeMaterializationResponsibility
[ ]: llvm_sys::orc2::LLVMOrcDisposeMaterializationUnit
[ ]: llvm_sys::orc2::LLVMOrcDisposeObjectLayer
[ ]: llvm_sys::orc2::LLVMOrcDisposeSymbols
[x]: llvm_sys::orc2::LLVMOrcDisposeThreadSafeContext
[x]: llvm_sys::orc2::LLVMOrcDisposeThreadSafeModule
[x]: llvm_sys::orc2::LLVMOrcDumpObjectsRef
[x]: llvm_sys::orc2::LLVMOrcDumpObjects_CallOperator
[ ]: llvm_sys::orc2::LLVMOrcErrorReporterFunction
[ ]: llvm_sys::orc2::LLVMOrcExecutionSessionCreateBareJITDylib
[ ]: llvm_sys::orc2::LLVMOrcExecutionSessionCreateJITDylib
[ ]: llvm_sys::orc2::LLVMOrcExecutionSessionGetJITDylibByName
[ ]: llvm_sys::orc2::LLVMOrcExecutionSessionGetSymbolStringPool
[ ]: llvm_sys::orc2::LLVMOrcExecutionSessionIntern
[ ]: llvm_sys::orc2::LLVMOrcExecutionSessionLookup
[ ]: llvm_sys::orc2::LLVMOrcExecutionSessionLookupHandleResultFunction
[ ]: llvm_sys::orc2::LLVMOrcExecutionSessionRef
[ ]: llvm_sys::orc2::LLVMOrcExecutionSessionSetErrorReporter
[ ]: llvm_sys::orc2::LLVMOrcExecutorAddress
[x]: llvm_sys::orc2::LLVMOrcGenericIRModuleOperationFunction
[ ]: llvm_sys::orc2::LLVMOrcIRTransformLayerEmit
[ ]: llvm_sys::orc2::LLVMOrcIRTransformLayerRef
[ ]: llvm_sys::orc2::LLVMOrcIRTransformLayerSetTransform
[ ]: llvm_sys::orc2::LLVMOrcIRTransformLayerTransformFunction
[x]: llvm_sys::orc2::LLVMOrcIndirectStubsManagerRef
[ ]: llvm_sys::orc2::LLVMOrcJITDylibAddGenerator
[x]: llvm_sys::orc2::LLVMOrcJITDylibClear
[ ]: llvm_sys::orc2::LLVMOrcJITDylibCreateResourceTracker
[ ]: llvm_sys::orc2::LLVMOrcJITDylibDefine
[ ]: llvm_sys::orc2::LLVMOrcJITDylibGetDefaultResourceTracker
[x]: llvm_sys::orc2::LLVMOrcJITDylibLookupFlags
[ ]: llvm_sys::orc2::LLVMOrcJITDylibRef
[ ]: llvm_sys::orc2::LLVMOrcJITTargetAddress
[x]: llvm_sys::orc2::LLVMOrcJITTargetMachineBuilderCreateFromTargetMachine
[x]: llvm_sys::orc2::LLVMOrcJITTargetMachineBuilderDetectHost
[x]: llvm_sys::orc2::LLVMOrcJITTargetMachineBuilderGetTargetTriple
[x]: llvm_sys::orc2::LLVMOrcJITTargetMachineBuilderRef
[x]: llvm_sys::orc2::LLVMOrcJITTargetMachineBuilderSetTargetTriple
[ ]: llvm_sys::orc2::LLVMOrcLazyCallThroughManagerRef
[ ]: llvm_sys::orc2::LLVMOrcLazyReexports
[x]: llvm_sys::orc2::LLVMOrcLookupKind
[ ]: llvm_sys::orc2::LLVMOrcLookupStateContinueLookup
[ ]: llvm_sys::orc2::LLVMOrcLookupStateRef
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityAddDependencies
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityAddDependenciesForAll
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityDefineMaterializing
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityDelegate
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityFailMaterialization
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityGetExecutionSession
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityGetInitializerSymbol
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityGetRequestedSymbols
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityGetSymbols
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityGetTargetDylib
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityNotifyEmitted
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityNotifyResolved
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityRef
[ ]: llvm_sys::orc2::LLVMOrcMaterializationResponsibilityReplace
[ ]: llvm_sys::orc2::LLVMOrcMaterializationUnitDestroyFunction
[ ]: llvm_sys::orc2::LLVMOrcMaterializationUnitDiscardFunction
[ ]: llvm_sys::orc2::LLVMOrcMaterializationUnitMaterializeFunction
[ ]: llvm_sys::orc2::LLVMOrcMaterializationUnitRef
[ ]: llvm_sys::orc2::LLVMOrcObjectLayerAddObjectFile
[ ]: llvm_sys::orc2::LLVMOrcObjectLayerAddObjectFileWithRT
[ ]: llvm_sys::orc2::LLVMOrcObjectLayerEmit
[ ]: llvm_sys::orc2::LLVMOrcObjectLayerRef
[ ]: llvm_sys::orc2::LLVMOrcObjectLinkingLayerRef
[ ]: llvm_sys::orc2::LLVMOrcObjectTransformLayerRef
[ ]: llvm_sys::orc2::LLVMOrcObjectTransformLayerSetTransform
[ ]: llvm_sys::orc2::LLVMOrcObjectTransformLayerTransformFunction
[ ]: llvm_sys::orc2::LLVMOrcOpaqueDefinitionGenerator
[ ]: llvm_sys::orc2::LLVMOrcOpaqueDumpObjects
[ ]: llvm_sys::orc2::LLVMOrcOpaqueExecutionSession
[ ]: llvm_sys::orc2::LLVMOrcOpaqueIRTransformLayer
[ ]: llvm_sys::orc2::LLVMOrcOpaqueIndirectStubsManager
[ ]: llvm_sys::orc2::LLVMOrcOpaqueJITDylib
[ ]: llvm_sys::orc2::LLVMOrcOpaqueJITTargetMachineBuilder
[ ]: llvm_sys::orc2::LLVMOrcOpaqueLazyCallThroughManager
[ ]: llvm_sys::orc2::LLVMOrcOpaqueLookupState
[ ]: llvm_sys::orc2::LLVMOrcOpaqueMaterializationResponsibility
[ ]: llvm_sys::orc2::LLVMOrcOpaqueMaterializationUnit
[ ]: llvm_sys::orc2::LLVMOrcOpaqueObjectLayer
[ ]: llvm_sys::orc2::LLVMOrcOpaqueObjectLinkingLayer
[ ]: llvm_sys::orc2::LLVMOrcOpaqueObjectTransformLayer
[ ]: llvm_sys::orc2::LLVMOrcOpaqueResourceTracker
[ ]: llvm_sys::orc2::LLVMOrcOpaqueSymbolStringPool
[ ]: llvm_sys::orc2::LLVMOrcOpaqueSymbolStringPoolEntry
[ ]: llvm_sys::orc2::LLVMOrcOpaqueThreadSafeContext
[ ]: llvm_sys::orc2::LLVMOrcOpaqueThreadSafeModule
[ ]: llvm_sys::orc2::LLVMOrcQuaqueSymbolStringPoolEntry
[x]: llvm_sys::orc2::LLVMOrcReleaseResourceTracker
[ ]: llvm_sys::orc2::LLVMOrcReleaseSymbolStringPoolEntry
[x]: llvm_sys::orc2::LLVMOrcResourceTrackerRef
[x]: llvm_sys::orc2::LLVMOrcResourceTrackerRemove
[x]: llvm_sys::orc2::LLVMOrcResourceTrackerTransferTo
[ ]: llvm_sys::orc2::LLVMOrcRetainSymbolStringPoolEntry
[x]: llvm_sys::orc2::LLVMOrcSymbolLookupFlags
[ ]: llvm_sys::orc2::LLVMOrcSymbolPredicate
[ ]: llvm_sys::orc2::LLVMOrcSymbolStringPoolClearDeadEntries
[ ]: llvm_sys::orc2::LLVMOrcSymbolStringPoolEntryRef
[ ]: llvm_sys::orc2::LLVMOrcSymbolStringPoolEntryStr
[ ]: llvm_sys::orc2::LLVMOrcSymbolStringPoolRef
[ ]: llvm_sys::orc2::LLVMOrcThreadSafeContextGetContext
[x]: llvm_sys::orc2::LLVMOrcThreadSafeContextRef
[x]: llvm_sys::orc2::LLVMOrcThreadSafeModuleRef
[x]: llvm_sys::orc2::LLVMOrcThreadSafeModuleWithModuleDo
[ ]: llvm_sys::orc2::ee
    [ ]: llvm_sys::orc2::ee::LLVMMemoryManagerCreateContextCallback
    [ ]: llvm_sys::orc2::ee::LLVMMemoryManagerNotifyTerminatingCallback
    [ ]: llvm_sys::orc2::ee::LLVMOrcCreateObjectLinkingLayerWithInProcessMemoryManager
    [ ]: llvm_sys::orc2::ee::LLVMOrcCreateRTDyldObjectLinkingLayerWithMCJITMemoryManagerLikeCallbacks
    [ ]: llvm_sys::orc2::ee::LLVMOrcCreateRTDyldObjectLinkingLayerWithSectionMemoryManager
    [ ]: llvm_sys::orc2::ee::LLVMOrcCreateRTDyldObjectLinkingLayerWithSectionMemoryManagerReserveAlloc
    [ ]: llvm_sys::orc2::ee::LLVMOrcRTDyldObjectLinkingLayerRegisterJITEventListener
[ ]: llvm_sys::orc2::lljit
    [x]: llvm_sys::orc2::lljit::LLVMOrcCreateLLJIT
    [x]: llvm_sys::orc2::lljit::LLVMOrcCreateLLJITBuilder
    [x]: llvm_sys::orc2::lljit::LLVMOrcDisposeLLJIT
    [x]: llvm_sys::orc2::lljit::LLVMOrcDisposeLLJITBuilder
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITAddLLVMIRModule
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITAddLLVMIRModuleWithRT
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITAddObjectFile
    [x]: llvm_sys::orc2::lljit::LLVMOrcLLJITAddObjectFileWithRT
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITBuilderObjectLinkingLayerCreatorFunction
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITBuilderRef
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITBuilderSetJITTargetMachineBuilder
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITBuilderSetObjectLinkingLayerCreator
    [x]: llvm_sys::orc2::lljit::LLVMOrcLLJITEnableDebugSupport
    [x]: llvm_sys::orc2::lljit::LLVMOrcLLJITGetDataLayoutStr
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITGetExecutionSession
    [x]: llvm_sys::orc2::lljit::LLVMOrcLLJITGetGlobalPrefix
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITGetIRTransformLayer
    [x]: llvm_sys::orc2::lljit::LLVMOrcLLJITGetMainJITDylib
    [x]: llvm_sys::orc2::lljit::LLVMOrcLLJITGetObjLinkingLayer
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITGetObjTransformLayer
    [x]: llvm_sys::orc2::lljit::LLVMOrcLLJITGetTripleString
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITLookup
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITMangleAndIntern
    [ ]: llvm_sys::orc2::lljit::LLVMOrcLLJITRef
    [ ]: llvm_sys::orc2::lljit::LLVMOrcOpaqueLLJIT
    [ ]: llvm_sys::orc2::lljit::LLVMOrcOpaqueLLJITBuilder
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

# ORC Design and Implementation Notes:
[https://llvm.org/docs/ORCv2.html]

## Eager and Lazy Compilation
ORC uses eager compilation by default, and will compile symbols
as soon as they are looked up in the JIT session object.
There is also support for lazy compilation, of course.

*/
