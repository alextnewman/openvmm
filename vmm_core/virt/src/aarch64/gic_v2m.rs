// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GIC SPI doorbell support for delivering PCIe MSIs as SPI assertions.

use crate::irqcon::ControlGic;
use aarch64defs::gic::GicV2mRegister;
use aarch64defs::gic::GicdRegister;
use pci_core::msi::SignalMsi;
use std::ops::Range;
use std::sync::Arc;
use vm_topology::processor::aarch64::GicV2mInfo;

/// Returns the permitted SPI range for an MSI doorbell address.
fn spi_range_for_msi_address(v2m: &GicV2mInfo, address: u64) -> Option<Range<u32>> {
    fn range(base: u32, count: u32) -> Option<Range<u32>> {
        let end = base.checked_add(count)?;
        (base < end).then_some(base..end)
    }

    if v2m
        .frame_base
        .checked_add(GicV2mRegister::SETSPI_NS.0 as u64)
        == Some(address)
    {
        return range(v2m.spi_base, v2m.spi_count);
    }

    let mbi = v2m.mbi?;
    (mbi.base.checked_add(GicdRegister::SETSPI_NSR.0 as u64) == Some(address))
        .then(|| range(mbi.spi_base, mbi.spi_count))
        .flatten()
}

/// Returns whether an MSI message targets a configured doorbell and SPI.
pub fn is_valid_msi(v2m: &GicV2mInfo, address: u64, data: u32) -> bool {
    spi_range_for_msi_address(v2m, address).is_some_and(|range| range.contains(&data))
}

/// A [`SignalMsi`] implementation that decodes GIC SPI MSI writes and delivers
/// them through [`ControlGic`].
///
/// When a device fires an MSI it writes the assigned GIC interrupt ID to the
/// SETSPI_NS register inside the v2m frame (`frame_base + 0x0040`), or to the
/// GICv3 distributor's SETSPI_NSR register (`mbi_base + 0x0040`). Hyper-V
/// exposes the latter as a platform convention without setting
/// `GICD_TYPER.MBIS`; FreeBSD's Hyper-V ACPI path relies on that behavior.
pub struct GicV2mSignalMsi {
    v2m: GicV2mInfo,
    irqcon: Arc<dyn ControlGic>,
}

impl GicV2mSignalMsi {
    /// Create a new `GicV2mSignalMsi` from v2m frame info and a GIC controller.
    pub fn new(v2m: &GicV2mInfo, irqcon: Arc<dyn ControlGic>) -> Self {
        Self { v2m: *v2m, irqcon }
    }
}

impl SignalMsi for GicV2mSignalMsi {
    fn signal_msi(&self, _devid: Option<u32>, address: u64, data: u32) {
        let Some(spi_range) = spi_range_for_msi_address(&self.v2m, address) else {
            tracelimit::warn_ratelimited!(address, data, "unexpected GIC SPI MSI address");
            return;
        };
        if !spi_range.contains(&data) {
            tracelimit::warn_ratelimited!(data, "MSI data outside configured SPI range");
            return;
        }
        self.irqcon.set_spi_irq(data, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use vm_topology::processor::aarch64::GicMbiInfo;

    #[derive(Default)]
    struct TestGic {
        requests: Mutex<Vec<(u32, bool)>>,
    }

    impl ControlGic for TestGic {
        fn set_spi_irq(&self, irq_id: u32, high: bool) {
            self.requests.lock().push((irq_id, high));
        }
    }

    fn test_v2m() -> GicV2mInfo {
        GicV2mInfo {
            frame_base: 0x1000,
            mbi: Some(GicMbiInfo {
                base: 0x2000,
                spi_base: 64,
                spi_count: 2,
            }),
            spi_base: 128,
            spi_count: 2,
        }
    }

    #[test]
    fn accepts_v2m_and_gicv3_mbi_addresses() {
        let v2m = test_v2m();
        let irqcon = Arc::new(TestGic::default());
        let signal = GicV2mSignalMsi::new(&v2m, irqcon.clone());

        signal.signal_msi(None, 0x1040, 128);
        signal.signal_msi(None, 0x2040, 65);

        assert_eq!(*irqcon.requests.lock(), [(128, true), (65, true)]);
    }

    #[test]
    fn rejects_unknown_addresses_and_out_of_range_spis() {
        let v2m = test_v2m();
        let irqcon = Arc::new(TestGic::default());
        let signal = GicV2mSignalMsi::new(&v2m, irqcon.clone());

        signal.signal_msi(None, 0x3040, 128);
        signal.signal_msi(None, 0x1040, 127);
        signal.signal_msi(None, 0x2040, 66);

        assert!(irqcon.requests.lock().is_empty());
    }

    #[test]
    fn message_validation_uses_the_selected_doorbell_range() {
        let mut v2m = test_v2m();

        assert!(is_valid_msi(&v2m, 0x1040, 128));
        assert!(!is_valid_msi(&v2m, 0x1040, 64));
        assert!(is_valid_msi(&v2m, 0x2040, 64));
        assert!(!is_valid_msi(&v2m, 0x2040, 128));
        assert!(!is_valid_msi(&v2m, 0x3040, 128));

        v2m.mbi = None;
        assert!(!is_valid_msi(&v2m, 0x2040, 64));
    }

    #[test]
    fn mbi_accepts_the_full_advertised_spi_range() {
        let mut v2m = test_v2m();
        v2m.mbi = Some(GicMbiInfo {
            base: 0x2000,
            spi_base: 64,
            spi_count: 992 - 64,
        });

        assert!(is_valid_msi(&v2m, 0x2040, 64));
        assert!(is_valid_msi(&v2m, 0x2040, 991));
        assert!(!is_valid_msi(&v2m, 0x2040, 992));
    }

    #[test]
    fn empty_or_overflowing_ranges_are_rejected() {
        let mut v2m = test_v2m();

        v2m.spi_count = 0;
        assert_eq!(spi_range_for_msi_address(&v2m, 0x1040), None);

        v2m.frame_base = u64::MAX;
        assert_eq!(spi_range_for_msi_address(&v2m, 0x3f), None);

        v2m.mbi = Some(GicMbiInfo {
            base: u64::MAX,
            spi_base: u32::MAX,
            spi_count: 2,
        });
        assert_eq!(spi_range_for_msi_address(&v2m, 0x3f), None);

        v2m.mbi.as_mut().unwrap().base = 0x2000;
        assert_eq!(spi_range_for_msi_address(&v2m, 0x2040), None);
    }
}
