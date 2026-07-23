// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! PCIe Single Root I/O Virtualization (SR-IOV) extended capability.

use super::PciExtendedCapability;
use crate::spec::caps::ExtendedCapabilityId;
use crate::spec::caps::sriov::SriovExtendedCapabilityHeader;
use chipset_device::pci::ByteEnabledDwordRead;
use chipset_device::pci::ByteEnabledDwordWrite;
use inspect::Inspect;

/// Supported VF page-size bitmap advertising 4 KB pages (bit 0), the standard
/// minimum. Also the reset value of the (writable) system page size.
const SUPPORTED_PAGE_SIZES: u32 = 0x1;

/// Total size of the SR-IOV extended capability structure: the header plus 15
/// dwords, through the VF migration state array offset.
const SRIOV_CAP_LEN: usize = 0x40;

/// PCIe SR-IOV extended capability emulator.
///
/// This advertises a structurally complete SR-IOV capability that reports zero
/// virtual functions. A physical-function driver that requires the capability
/// to be present can read it and find no VFs to bring up, so no virtual-function
/// infrastructure is requested.
#[derive(Debug, Inspect)]
pub struct SriovExtendedCapability {
    control: u16,
    system_page_size: u32,
}

impl SriovExtendedCapability {
    /// Creates an SR-IOV capability reporting zero virtual functions.
    pub fn new() -> Self {
        Self {
            control: 0,
            system_page_size: SUPPORTED_PAGE_SIZES,
        }
    }
}

impl Default for SriovExtendedCapability {
    fn default() -> Self {
        Self::new()
    }
}

impl PciExtendedCapability for SriovExtendedCapability {
    fn label(&self) -> &str {
        "sriov"
    }

    fn extended_capability_id(&self) -> u16 {
        ExtendedCapabilityId::SRIOV.0
    }

    fn capability_version(&self) -> u8 {
        1
    }

    fn len(&self) -> usize {
        SRIOV_CAP_LEN
    }

    fn read(&self, offset: u16, mut value: ByteEnabledDwordRead<'_>) {
        match SriovExtendedCapabilityHeader(offset) {
            SriovExtendedCapabilityHeader::HEADER => {
                value.set_low_high(
                    self.extended_capability_id(),
                    self.capability_version().into(),
                );
            }
            SriovExtendedCapabilityHeader::CONTROL_STATUS => {
                value.set_low_high(self.control, 0);
            }
            // Initial and total VFs are both zero: no virtual functions are
            // advertised.
            SriovExtendedCapabilityHeader::INITIAL_TOTAL_VFS => value.set(0),
            SriovExtendedCapabilityHeader::SUPPORTED_PAGE_SIZES => {
                value.set(SUPPORTED_PAGE_SIZES);
            }
            SriovExtendedCapabilityHeader::SYSTEM_PAGE_SIZE => {
                value.set(self.system_page_size);
            }
            // The SR-IOV capabilities register, VF count/offset/stride, VF device
            // id, and the VF BARs are all zero when no virtual functions exist.
            _ => value.set(0),
        }
    }

    fn write(&mut self, offset: u16, val: ByteEnabledDwordWrite) {
        match SriovExtendedCapabilityHeader(offset) {
            SriovExtendedCapabilityHeader::CONTROL_STATUS => {
                // Only the control half (low 16 bits) is writable; the status
                // half is read-only here. Control is inert because no virtual
                // functions are advertised.
                self.control = val.merge_low(self.control);
            }
            SriovExtendedCapabilityHeader::SYSTEM_PAGE_SIZE => {
                self.system_page_size = val.merge(self.system_page_size);
            }
            _ => {
                tracelimit::warn_ratelimited!(
                    offset,
                    ?val,
                    "write to read-only SR-IOV extended capability register"
                );
            }
        }
    }

    fn reset(&mut self) {
        self.control = 0;
        self.system_page_size = SUPPORTED_PAGE_SIZES;
    }
}

mod save_restore {
    use super::*;
    use vmcore::save_restore::RestoreError;
    use vmcore::save_restore::SaveError;
    use vmcore::save_restore::SaveRestore;

    mod state {
        use mesh::payload::Protobuf;
        use vmcore::save_restore::SavedStateRoot;

        #[derive(Debug, Protobuf, SavedStateRoot)]
        #[mesh(package = "pci.capabilities.extended.sriov")]
        pub struct SavedState {
            #[mesh(1)]
            pub control: u16,
            #[mesh(2)]
            pub system_page_size: u32,
        }
    }

    impl SaveRestore for SriovExtendedCapability {
        type SavedState = state::SavedState;

        fn save(&mut self) -> Result<Self::SavedState, SaveError> {
            Ok(state::SavedState {
                control: self.control,
                system_page_size: self.system_page_size,
            })
        }

        fn restore(&mut self, state: Self::SavedState) -> Result<(), RestoreError> {
            self.control = state.control;
            self.system_page_size = state.system_page_size;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::extended::assert_extended_header_contract;
    use crate::test_helpers::read_extended_cap_u32;
    use crate::test_helpers::write_extended_cap_u32;
    use vmcore::save_restore::SaveRestore;

    #[test]
    fn test_sriov_defaults() {
        let cap = SriovExtendedCapability::new();

        assert_eq!(cap.label(), "sriov");
        assert_eq!(cap.extended_capability_id(), ExtendedCapabilityId::SRIOV.0);
        assert_eq!(cap.capability_version(), 1);
        assert_eq!(cap.len(), SRIOV_CAP_LEN);
        assert_extended_header_contract(&cap);

        // No virtual functions advertised.
        assert_eq!(
            read_extended_cap_u32(&cap, SriovExtendedCapabilityHeader::INITIAL_TOTAL_VFS.0),
            0
        );
        // 4 KB page support, selected by default.
        assert_eq!(
            read_extended_cap_u32(&cap, SriovExtendedCapabilityHeader::SUPPORTED_PAGE_SIZES.0),
            SUPPORTED_PAGE_SIZES
        );
        assert_eq!(
            read_extended_cap_u32(&cap, SriovExtendedCapabilityHeader::SYSTEM_PAGE_SIZE.0),
            SUPPORTED_PAGE_SIZES
        );
    }

    #[test]
    fn test_sriov_system_page_size_rw() {
        let mut cap = SriovExtendedCapability::new();

        write_extended_cap_u32(
            &mut cap,
            SriovExtendedCapabilityHeader::SYSTEM_PAGE_SIZE.0,
            0x2,
        );
        assert_eq!(
            read_extended_cap_u32(&cap, SriovExtendedCapabilityHeader::SYSTEM_PAGE_SIZE.0),
            0x2
        );

        cap.reset();
        assert_eq!(
            read_extended_cap_u32(&cap, SriovExtendedCapabilityHeader::SYSTEM_PAGE_SIZE.0),
            SUPPORTED_PAGE_SIZES
        );
    }

    #[test]
    fn test_sriov_save_restore() {
        let mut cap = SriovExtendedCapability::new();
        write_extended_cap_u32(
            &mut cap,
            SriovExtendedCapabilityHeader::CONTROL_STATUS.0,
            0x1,
        );
        write_extended_cap_u32(
            &mut cap,
            SriovExtendedCapabilityHeader::SYSTEM_PAGE_SIZE.0,
            0x2,
        );

        let saved = cap.save().expect("save should succeed");

        cap.reset();
        cap.restore(saved).expect("restore should succeed");

        assert_eq!(
            read_extended_cap_u32(&cap, SriovExtendedCapabilityHeader::CONTROL_STATUS.0),
            0x1
        );
        assert_eq!(
            read_extended_cap_u32(&cap, SriovExtendedCapabilityHeader::SYSTEM_PAGE_SIZE.0),
            0x2
        );
    }
}
