// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]

fn main() {
    build_rs_guest_arch::emit_guest_arch();

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/simd_shim.c")
            .compile("virt_hvf_simd_shim");
    }
}
