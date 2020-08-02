use crate::spec::{base, CodeModel, Target};

pub fn target() -> Target {
    let mut base = base::redox::opts();
    base.code_model = Some(CodeModel::Medium);
    base.cpu = "generic-rv64".into();
    base.features = "+m,+a,+f,+d,+c".into();
    base.llvm_abiname = "lp64d".into();
    base.plt_by_default = false;
    base.max_atomic_width = Some(64);

    Target {
        llvm_target: "riscv64-unknown-redox".into(),
        metadata: crate::spec::TargetMetadata {
            description: None,
            tier: None,
            host_tools: None,
            std: None,
        },
        pointer_width: 64,
        data_layout: "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128".into(),
        arch: "riscv64".into(),
        options: base
    }
}
