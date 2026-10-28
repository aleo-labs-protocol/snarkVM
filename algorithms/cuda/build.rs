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
    // Set below once the kernels compile. `HAVE_NVCC` and the tests that call
    // the kernels read it.
    println!("cargo:rustc-check-cfg=cfg(have_nvcc)");
    // One `rerun-if-changed` replaces cargo's default of watching every file
    // in the package, so every source compiled below must be listed here.
    println!("cargo:rerun-if-changed=src/lib.c");
    println!("cargo:rerun-if-changed=cuda");
    println!("cargo:rerun-if-env-changed=CXXFLAGS");
    println!("cargo:rerun-if-env-changed=NVCC");
    println!("cargo:rerun-if-env-changed=CUDA_ARCH");
    // nvcc reads these two itself, so cc-rs does not declare them.
    println!("cargo:rerun-if-env-changed=NVCC_APPEND_FLAGS");
    println!("cargo:rerun-if-env-changed=NVCC_PREPEND_FLAGS");

    let curve = "FEATURE_BLS12_377";

    // Set CC environment variable to choose an alternative C compiler.
    // Optimization level depends on whether or not --release is passed
    // or implied.
    let mut cc = cc::Build::new();

    let c_src_dir = PathBuf::from("src");
    let files = vec![c_src_dir.join("lib.c")];
    cc.flag_if_supported("-mno-avx") // avoid costly transitions
        .flag_if_supported("-fno-builtin")
        .flag_if_supported("-Wno-unused-command-line-argument");
    if !cfg!(debug_assertions) {
        cc.opt_level(2);
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
        // Host debug info only. cc-rs adds device debug (-G) when the profile has
        // debug on, and -G stops `xyzz_t::add` being inlined into `accumulate`.
        // nvlink then rejects the cross-module call: `accumulate` is
        // `__launch_bounds__`-capped at 168 registers while `add` is compiled
        // under -maxrregcount=255.
        nvcc.debug(false);
        nvcc.flag("-g");
<<<<<<< HEAD
        // Ampere (sm_86) by default. Its SASS also runs on Ada (sm_89), and
        // Hopper (sm_90) JIT-compiles its embedded PTX. CUDA_ARCH overrides it;
        // an empty value takes the default. A binary built for a newer arch than
        // the GPU fails every kernel launch.
        let arch = match env::var("CUDA_ARCH") {
            Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
            _ => "sm_86".to_string(),
        };
        nvcc.flag(format!("-arch={arch}"));
=======
        nvcc.flag("-arch=sm_86");
>>>>>>> e0a79a584ef6bfb3d8a8e569662d44d24623f227
        nvcc.flag("-maxrregcount=255");
        nvcc.flag("-Xcompiler").flag("-Wno-unused-function");
        nvcc.flag("-Xcompiler").flag("-Wno-subobject-linkage");
        nvcc.define("TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE", None);
        nvcc.define(curve, None);
        // `__ADX__` renames the symbols in blst's `vect.h`, so this crate and
        // blst must agree on it. Both build in blst's portable mode, whose
        // routines pick the ADX code at run time from CPUID.
        nvcc.define("__BLST_PORTABLE__", None);
        if let Some(include) = env::var_os("DEP_BLST_C_SRC") {
            nvcc.include(include);
        }
        if let Some(include) = env::var_os("DEP_SPPARK_ROOT") {
            nvcc.include(include);
        }
        nvcc.file("cuda/snarkvm_api.cu").compile("snarkvm_algorithms_cuda");

        println!("cargo:rustc-cfg=have_nvcc");
    } else {
        println!(
            "cargo:warning=nvcc not found: the CUDA kernels are not built. Put nvcc on PATH or set NVCC to its path."
        );
    }
}
