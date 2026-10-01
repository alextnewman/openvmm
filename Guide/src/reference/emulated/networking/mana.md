# MANA / GDMA protocol examination

The `gdma` emulator can passively examine the actions of its guest driver.
The separate `gdma_contract` crate maintains a two-sided contract over
observed byte images and resource transitions. It does not call the
emulator's admission checks, WQE codec, or mutable ownership ledger.

This is an examiner of a modeled protocol slice, not firmware or physical
hardware conformance certification. It evaluates the same observations
regardless of the guest operating system.

## Enable the examiner

Add `--mana-protocol-monitor` to a configuration with an explicit `--mana`
device. The examiner is disabled by default and does not change device
admission or command status.

```bash
openvmm --mana consomme:10.0.0.0/24 --mana-protocol-monitor <VM_OPTIONS>
```

The flag applies to the explicitly configured MANA devices, including PCIe
and virtual PCI presentations. Programmatic configurations can set
`GdmaDeviceHandle::protocol_monitor` or `BnicConfig::protocol_monitor`.

Find the device's `protocol` node through the
[interactive inspector](../../openvmm/management/interactive_console.md).
It exposes the observation scope, epochs, per-rule satisfied and violation
counts, inconclusive observations, unmodeled commands, and bounded scalar
findings. Findings also produce rate-limited trace warnings with an actor,
rule ID, sequence, queue identity, and witnesses.

Evidence retains at most 64 findings. Omitted-record counts remain visible.
Reset begins a new ownership epoch without deleting earlier findings.
There is no whole-driver "compliant" result derived from an empty error log.

## Implemented contract slice

The rules cover aligned SMC and atomic doorbell publication, type-qualified
queue identities, bound ring geometry, published work windows, legacy WQE
extents, device consumption, owner phases, completion storage and routing,
consumer generations, SMC response correlation, standard HWC envelopes,
response correlation, and known resource transitions.

HWC initialization is decoded from the actual published EQE bytes.
Descriptor snapshots are captured from published queue storage before the
emulator's payload decoder. HWC payload projection is independently
implemented for legacy GPA-addressed SGLs with 8- or 24-byte inline OOB,
without direct SGL or client-OOB-in-SGL encodings. Unsupported forms and
unavailable byte images are inconclusive, not guest violations.

Successful V1 replies drive region creation and continuation, free-handle
transfer to queues, work-queue-object binding, destruction, and receive
fence reference checks. A rejected resource request does not itself
constitute a driver violation. A successful unsafe known transition is
attributed to the device.

## Observation assumptions

Native guest memory reads are not intercepted. A notification doorbell is
not a complete record of CQ consumption. When the last observed consumer
publication cannot establish available space, native examination records
an inconclusive completion window rather than an overflow violation.
Controlled traces can explicitly declare complete consumer observations.

The monitor observes the emulator's bound DMA queue images. It does not
prove descriptor placement, address-translation permissions, memory-key
resolution, guest CPU barriers, physical PCIe/cache ordering, or guest OS
DMA allocation, unmap, and free. It does not establish per-packet
completion-to-buffer-release correspondence, packet offload or RSS
correctness, moderation timing, or scheduling liveness.

Each finding remains conditional on its rule's scope and observations.
Unknown command or reply versions are not treated as illegal variation.
In particular, a timeout does not prove rejection or released ownership.

## Checking the examiner

The ordinary `gdma_contract` tests use independently encoded valid and
invalid wire examples, explicit actor attribution, cursor rollover, and an
independent finite-state reference explorer. The explorer covers two
two-entry event rings, three-bit owner phases, publication, rearm,
retirement, reuse, and all reachable interleavings in that bounded model.
It checks both legal actions and selected invalid successors.

```bash
cargo test -p gdma_contract
cargo run -p gdma_contract --example contract_probe
python3 repo_support/check_gdma_contract_mutations.py
```

The mutation check first requires the unmodified corpus to pass. Each
mutant must compile and then fail its executable example. It checks missed
violations and false accusations; compilation failures and timeouts do not
count as detection. It uses the existing Rust compiler and no downloaded
testing framework.

The `mana_driver` requester regression enables the examiner through a
complete modeled setup and resource teardown, requires exercised rules,
and rejects false findings. These host-side tests qualify the monitor and
its adapter, not a Linux or FreeBSD kernel driver. Native driver claims
require actual guest execution with exact emulator, driver, and kernel
identities.

Model exploration establishes consistency only within its stated model
and bounds. Independent wire examples, mutations, and requester replay
check different failure modes; none alone proves that the contract's
interpretation describes physical hardware.
