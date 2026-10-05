#!/usr/bin/env python3

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Compile contract defects and require independent executable detection."""

import argparse
from pathlib import Path
import shlex
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "vm/devices/net/gdma_contract/src/lib.rs"
PROBE = ROOT / "vm/devices/net/gdma_contract/examples/contract_probe.rs"
MUTATIONS = (
    (
        "duplicate-queue-binding-accepted",
        "typed-lifetime",
        "Rule::QueueLifetime, Actor::Device, !self.queues.contains_key(&key),",
        "Rule::QueueLifetime, Actor::Device, true,",
    ),
    (
        "partial-doorbell-accepted",
        "atomic-publication",
        "data.len() == 8 && offset == base",
        "offset == base",
    ),
    (
        "unaligned-tail-accepted",
        "work-publication",
        "tail.is_multiple_of(WORK_ALIGNMENT)",
        "true",
    ),
    (
        "unpublished-consumption",
        "device-consumption",
        "bytes <= state.producer.wrapping_sub(state.consumer)",
        "true",
    ),
    (
        "incorrect-owner-accepted",
        "owner-phases",
        "observed_owner == expected_owner",
        "true",
    ),
    (
        "correlation-ignored",
        "reply-correlation",
        "read32(bytes, 20) == Some(request.activity)",
        "true",
    ),
    (
        "native-gap-blamed-on-device",
        "native-consumer-gap",
        "self.scope == ObservationScope::CompleteConsumerTrace || window_known",
        "true",
    ),
    (
        "legal-stale-rearm-rejected",
        "legal-rearm-hints",
        "let valid = distance <= state.capacity(key.kind);",
        "let valid = distance <= state.capacity(key.kind) && distance <= previous;",
    ),
    (
        "legal-short-rejection-rejected",
        "legal-short-rejection",
        "wire_len <= request.capacity && wire_len <= request.limit",
        "wire_len <= request.capacity && wire_len == request.limit",
    ),
    (
        "driver-version-read-from-capabilities",
        "driver-declaration",
        "driver_version: read64(bytes, 88)?",
        "driver_version: read64(bytes, 80)?",
    ),
    (
        "reset-retains-driver-declaration",
        "driver-declaration",
        "self.vport_limits = None; self.driver_declaration = None; self.max_request = 0;",
        "self.vport_limits = None; self.max_request = 0;",
    ),
    (
        "invalid-identity-lossily-attested",
        "driver-declaration",
        "std::str::from_utf8(&field[..end]).ok()?.to_owned()",
        "String::from_utf8_lossy(&field[..end]).into_owned()",
    ),
)


def execute(command, timeout=120):
    result = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    return result.returncode, result.stdout


def compile_probe(rustc, source, directory):
    library = directory / "libgdma_contract.rlib"
    binary = directory / "contract_probe"
    code, output = execute(
        [
            *rustc,
            "--edition=2024",
            "--crate-type=rlib",
            "--crate-name=gdma_contract",
            "-Wmissing_docs",
            str(source),
            "-o",
            str(library),
        ]
    )
    if code != 0:
        raise RuntimeError(f"contract library did not compile:\n{output}")
    code, output = execute(
        [
            *rustc,
            "--edition=2024",
            str(PROBE),
            "--extern",
            f"gdma_contract={library}",
            "-o",
            str(binary),
        ]
    )
    if code != 0:
        raise RuntimeError(f"independent probe did not compile:\n{output}")
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--build-dir", type=Path, default=ROOT / "target/gdma-contract-mutations")
    args = parser.parse_args()
    rustc = shlex.split(args.rustc)
    args.build_dir.mkdir(parents=True, exist_ok=True)
    contents = SOURCE.read_text()
    with tempfile.TemporaryDirectory(prefix="run-", dir=args.build_dir) as temporary:
        scratch = Path(temporary)
        baseline = compile_probe(rustc, SOURCE, scratch)
        code, output = execute([str(baseline)], timeout=10)
        if code != 0:
            raise RuntimeError(f"unmodified contract failed:\n{output}")
        for name, case, before, after in MUTATIONS:
            pattern = re.compile(r"\s+".join(re.escape(token) for token in before.split()))
            matches = list(pattern.finditer(contents))
            if len(matches) != 1:
                raise RuntimeError(f"ambiguous mutation anchor: {name}")
            mutant = scratch / "lib.rs"
            match = matches[0]
            mutant.write_text(contents[: match.start()] + after + contents[match.end() :])
            binary = compile_probe(rustc, mutant, scratch)
            code, output = execute([str(binary), case], timeout=10)
            if code == 0:
                raise RuntimeError(f"contract mutation survived: {name}\n{output}")
            print(f"GDMA contract mutation detected: {name} ({case})", flush=True)
    print(f"GDMA CONTRACT MUTATIONS OK ({len(MUTATIONS)} compiled defects detected)")


if __name__ == "__main__":
    main()
