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

### Machine-readable evidence

The `protocol/report_json` scalar exports `openvmm/gdma-protocol/v1`. It contains the same atomic monitor snapshot as the human rule tree: scope, epoch, observation sequence, rule counters, findings, completeness flags, and unobservable obligations. It also contains independently decoded request/response exchanges grouped by opcode, request version, requested reply version, actual reply version, status, and correlation, with counts, sequence bounds, and actual length ranges. The bounded table retains at most 128 keys; omitted exchanges are explicit.

The ownership summary counts type-qualified live queues, unconsumed region handles, work objects, and HWC lifetime. Region handles are not DMA backing allocations, and queue IDs are opaque identities rather than capacity counts. Global limits and the latest V1 per-vport SQ/RQ/indirection grant come from actual correlated query replies, not emulator configuration. A one-queue packet backend's vport grant is distinct from the function's GDMA inventory. Reset clears current ownership and grants while cumulative observations, exchanges, and findings remain available. A collector must join its guest boot and device epoch, verify monotonic counters, and preserve omitted, unknown, and inconclusive evidence.

`driver_declaration` independently decodes the complete V1 verify-driver request before a reply or successful probe is required. It retains the observation epoch/sequence, protocol range, four capability words, packed driver version, OS type/version and four bounded, NUL-terminated UTF-8 advisory strings. Reset or a new undecodable verify request clears it. These are guest declarations, not authenticated source identity: string meanings belong to the requester, and a collector must corroborate the loaded artifact and current boot independently. Missing or undecodable strings do not become protocol violations.

## Explicit device scenarios

`--mana-conformance-scenario <NAME>` requires both `--mana` and `--mana-protocol-monitor`. It is separate from the passive contract; findings do not change admission, and scenario declarations do not establish coverage.

| Name | Actual device behavior |
|------|------------------------|
| `baseline` | Ordinary behavior, identical to leaving scenarios disabled. |
| `constrained-eqs` | Both GDMA and MANA advertise four EQs, including HWC, and the allocator enforces that same grant. SQ, RQ, CQ and MSI-X limits are unchanged. |
| `short-stat-error` | The first optional MANA statistics or PHY-statistics query is rejected before dispatch with status 31 and an actual 32-byte response. No ownership-changing command is intercepted. |
| `bad-correlation` | The first successful read-only GDMA resource-query reply has its HWC response cookie changed before writing guest memory and publishing completion. The examiner must attribute the correlation violation to the device. |

One-shot controls apply once per emulated device lifetime, not once per request or guest reboot. Use a separate cold VM with the intended driver already installed for each scenario. A bad-device test must check the exact actor/rule and independent guest refusal; expecting all counters to remain zero would make it an ineffective control. Header-only legal rejection must preserve usable service rather than become a false protocol accusation.

## Implemented contract slice

The rules cover aligned SMC and atomic doorbell publication, type-qualified
queue identities, bound ring geometry, published work windows, legacy WQE
extents, device consumption, owner phases, completion storage and routing,
consumer generations, SMC response correlation, standard HWC envelopes,
response correlation, and known resource transitions.

HWC initialization is decoded from the actual published EQE bytes.
Host-function presentations, including bare-metal host mode, publish explicit
destination RQ and CQ initialization records before initialization completion.
These identify the emulator's remote management endpoint zero, not the guest's
allocated receive or completion queue. Ordinary VF initialization retains its
implicit destination and existing routing behavior. Host-function requests must
address their advertised remote endpoint; an unknown destination stops the HWC
task with an error. This explicit-destination check does not impose a new route
constraint on VF requests.

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

Receive suspension does not release already-posted buffers belonging to a still-live work object. The datapath retains those consumed descriptors under the opaque object handle and re-arms them in FIFO post order on enable. A successful fence, receive-object destroy or device reset clears the corresponding suspended state; reused numeric queue IDs cannot inherit a destroyed object's buffers. This preserves the same ownership truth as live steering without mistaking administrative quiet for release.

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

A separate published-EQ regression decodes bootstrap storage independently of
the requester's permissive initialization parser. It checks the unchanged VF
record sequence and both BM peer-destination records before completion, with
remote identities distinct from the guest queues. This does not add a
PCI-role-dependent mandatory-field rule to the passive examiner.

Model exploration establishes consistency only within its stated model
and bounds. Independent wire examples, mutations, and requester replay
check different failure modes; none alone proves that the contract's
interpretation describes physical hardware.
