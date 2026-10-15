// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{env, path::PathBuf};

fn main() {
    let curve = "FEATURE_BLS12_377";

    // Set CC environment variable to choose an alternative C compiler.
    // Optimization level depends on whether or not --release is passed
    // or implied.
    let mut cc = cc::Build::new();

    let c_src_dir = PathBuf::from("src");
    let files = vec![c_src_dir.join("lib.c")];
    let mut cc_opt = None;

    match cfg!(feature = "portable") {
        true => {
            println!("Compiling in portable mode without ISA extensions");
            cc_opt = Some("__BLST_PORTABLE__");
        }
        false => {
            #[cfg(target_arch = "x86_64")]
            {
                // account for cross-compilation [by examining environment variable]
                let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
                if target_arch.eq("x86_64") && std::is_x86_feature_detected!("adx") {
                    println!("Enabling ADX because it was detected on the host");
                    cc_opt = Some("__ADX__");
                }
            }
        }
    }

    cc.flag_if_supported("-mno-avx") // avoid costly transitions
        .flag_if_supported("-fno-builtin")
        .flag_if_supported("-Wno-unused-command-line-argument");
    if !cfg!(debug_assertions) {
        cc.opt_level(2);
    }
    if let Some(def) = cc_opt {
        cc.define(def, None);
    }
    if let Some(include) = env::var_os("DEP_BLST_C_SRC") {
        cc.include(include);
    }
    cc.files(&files).compile("blst_msm");

    if cfg!(target_os = "windows") && !cfg!(target_env = "msvc") {
        return;
    }
    // Detect if there is CUDA compiler and engage "cuda" feature accordingly
    let nvcc = match env::var("NVCC") {
        Ok(var) => which::which(var),
        Err(_) => which::which("nvcc"),
    };

    if nvcc.is_ok() {
        let mut nvcc = cc::Build::new();
        nvcc.cuda(true);
        nvcc.flag("-g");
        nvcc.flag("-arch=sm_86");
        nvcc.flag("-maxrregcount=255");
        nvcc.flag("-Xcompiler").flag("-Wno-unused-function");
        nvcc.flag("-Xcompiler").flag("-Wno-subobject-linkage");
        nvcc.define("TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE", None);
        nvcc.define(curve, None);
        if let Some(def) = cc_opt {
            nvcc.define(def, None);
        }
        if let Some(include) = env::var_os("DEP_BLST_C_SRC") {
            nvcc.include(include);
        }
        if let Some(include) = env::var_os("DEP_SPPARK_ROOT") {
            nvcc.include(include);
        }
        nvcc.file("cuda/snarkvm_api.cu").compile("snarkvm_algorithms_cuda");

        println!("cargo:rustc-cfg=feature=\"cuda\"");
        println!("cargo:rerun-if-changed=cuda");
        println!("cargo:rerun-if-env-changed=CXXFLAGS");
    } else {
        println!("nvcc must be in the path. Consider adding /usr/local/cuda/bin.");
        // panic!();
    }
}
