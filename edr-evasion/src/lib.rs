pub mod structural_invariants;

pub use etw_patch_sim::{
    EtwFunctionBuffer,
    PatchError,
    IntegrityStatus,
    ExecutionFlow,
    DetectionAlert,
    EdrDetectionSimulator,
    run_etw_patch_scenario,
};
