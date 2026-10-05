# Raw AArch64 Direct Boot

OpenVMM can load an opaque AArch64 executable image without firmware or a
Linux image header. This supports boot images that carry their own startup
program and operating-system payload.

## Boot contract

For a raw image, OpenVMM:

1. starts guest RAM at 1 GiB;
2. loads the complete file 512 KiB above the first RAM address;
3. begins execution at the first byte of the loaded image;
4. places the full hardware device tree at least 128 MiB into RAM, outside the
   image's early scratch space, and passes its address in `x0`; and
5. uses the configured virtual-timer interrupt (INTID 20 by default); and
6. enters at EL1 with the MMU disabled.

The default load and entry address is therefore `0x40080000`. Raw direct boot
does not support a separate initrd.

## Image selection

`--kernel-format auto` is the default. On AArch64, OpenVMM checks for the Linux
`ARM\x64` image magic and uses raw loading when that header is absent. Use
`--kernel-format linux` for strict Linux-image validation or
`--kernel-format raw` to force raw loading.

```bash
openvmm --kernel path/to/image.bin --kernel-format raw
```

## MMIO aliases

Some boot images access a PL011 UART at a fixed address instead of discovering
the canonical OpenVMM address from the device tree. A direct-boot VM can map an
additional address to the same UART instance:

```bash
openvmm --kernel path/to/image.bin \
    --com1 console,mmio_base_alias=0x09000000
```

The alias shares the canonical UART's complete device state, backend, and
interrupt. It is not emitted in ACPI or the device tree. Alias ranges must be
4 KiB aligned and fit below the 1 GiB direct-boot RAM base.

## Fixed virtio-MMIO

Firmware-less guests may also require virtio devices at predetermined
addresses and interrupts. Device options use `mmio_base` for the explicit
0x200-byte MMIO window and `mmio_gsiv` for the full GIC interrupt ID:

```bash
openvmm --kernel path/to/image.bin \
    --virt-timer-gsiv 27 \
    --virtio-blk file:path/to/disk.raw,mmio_base=0x0a003e00,mmio_gsiv=79 \
    --virtio-rng mmio_base=0x0a003a00,mmio_gsiv=77 \
    --virtio-net mmio_base=0x0a003c00:mmio_gsiv=78:consomme
```

Fixed virtio-MMIO placement is limited to AArch64 direct boot and must fit
below the 1 GiB RAM base. It is mutually exclusive with PCIe placement.
OpenVMM emits each fixed transport as a `virtio,mmio` node in the generated
device tree. These addresses are not implicit defaults; the example explicitly
recreates three slots from QEMU's `virt` platform for a guest built against
that platform contract. The explicit virtual-timer GSIV likewise selects
QEMU's architectural virtual-timer PPI 11 (INTID 27).
