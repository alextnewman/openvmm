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
5. enters at EL1 with the MMU disabled.

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
    --serial-mmio-alias com1=0x09000000
```

The alias shares the canonical UART's complete device state, backend, and
interrupt. It is not emitted in ACPI or the device tree. Alias ranges must be
4 KiB aligned and fit below the 1 GiB direct-boot RAM base.
