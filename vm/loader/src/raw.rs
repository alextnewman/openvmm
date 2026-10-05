// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Raw executable image loading.

use crate::common::ChunkBuf;
use crate::common::ImportFileRegion;
use crate::common::ImportFileRegionError;
use crate::importer::Aarch64Register;
use crate::importer::BootPageAcceptance;
use crate::importer::ImageLoad;
use hvdef::HV_PAGE_SIZE;
use std::io::Read;
use std::io::Seek;
use thiserror::Error;

/// Conventional load offset for raw AArch64 direct-boot images.
pub const AARCH64_DEFAULT_LOAD_OFFSET: u64 = 0x0008_0000;
/// Conventional minimum device-tree offset from the start of AArch64 RAM.
pub const AARCH64_DEFAULT_DTB_OFFSET: u64 = 128 * 1024 * 1024;
const AARCH64_DTB_ALIGNMENT: u64 = 2 * 1024 * 1024;

/// Information about a loaded raw image.
#[derive(Debug)]
pub struct LoadInfo {
    /// Guest-physical range occupied by the image file.
    pub image: std::ops::Range<u64>,
    /// Guest-physical entry point.
    pub entrypoint: u64,
    /// Guest-physical range occupied by the device tree.
    pub dtb: Option<std::ops::Range<u64>>,
}

/// An error returned while loading a raw image.
#[derive(Debug, Error)]
pub enum Error {
    /// The image load address is not page aligned.
    #[error("raw image load address is not page aligned: {0:#x}")]
    UnalignedLoadAddress(u64),
    /// The image contains no data.
    #[error("raw image is empty")]
    EmptyImage,
    /// An address or size calculation overflowed.
    #[error("raw image address calculation overflowed")]
    AddressOverflow,
    /// The image size could not be determined.
    #[error("failed to determine raw image size")]
    ImageSize(#[source] std::io::Error),
    /// The image could not be imported.
    #[error("failed to import raw image")]
    ImportImage(#[source] ImportFileRegionError),
    /// The device tree could not be imported.
    #[error("failed to import device tree")]
    ImportDeviceTree(#[source] anyhow::Error),
}

fn align_up_to_page_size(value: u64) -> Result<u64, Error> {
    value
        .checked_add(HV_PAGE_SIZE - 1)
        .map(|value| value & !(HV_PAGE_SIZE - 1))
        .ok_or(Error::AddressOverflow)
}

/// Load a raw AArch64 image and optional device tree.
pub fn load_arm64<F>(
    importer: &mut dyn ImageLoad<Aarch64Register>,
    image: &mut F,
    load_address: u64,
    device_tree_blob: Option<&[u8]>,
    device_tree_min_address: u64,
) -> Result<LoadInfo, Error>
where
    F: Read + Seek,
{
    if !load_address.is_multiple_of(HV_PAGE_SIZE) {
        return Err(Error::UnalignedLoadAddress(load_address));
    }

    let image_size = image
        .seek(std::io::SeekFrom::End(0))
        .map_err(Error::ImageSize)?;
    if image_size == 0 {
        return Err(Error::EmptyImage);
    }

    let image_memory_size = align_up_to_page_size(image_size)?;
    let image_file_end = load_address
        .checked_add(image_size)
        .ok_or(Error::AddressOverflow)?;
    let image_memory_end = load_address
        .checked_add(image_memory_size)
        .ok_or(Error::AddressOverflow)?;

    ChunkBuf::new()
        .import_file_region(
            importer,
            ImportFileRegion {
                file: image,
                file_offset: 0,
                file_length: image_size,
                gpa: load_address,
                memory_length: image_memory_size,
                acceptance: BootPageAcceptance::Exclusive,
                tag: "raw-kernel",
            },
        )
        .map_err(Error::ImportImage)?;

    let dtb = if let Some(device_tree_blob) = device_tree_blob {
        let dtb_size = device_tree_blob.len() as u64;
        let dtb_memory_size = align_up_to_page_size(dtb_size)?;
        let dtb_start = image_memory_end
            .max(device_tree_min_address)
            .checked_add(AARCH64_DTB_ALIGNMENT - 1)
            .map(|address| address & !(AARCH64_DTB_ALIGNMENT - 1))
            .ok_or(Error::AddressOverflow)?;
        let dtb_end = dtb_start
            .checked_add(dtb_size)
            .ok_or(Error::AddressOverflow)?;

        importer
            .import_pages(
                dtb_start / HV_PAGE_SIZE,
                dtb_memory_size / HV_PAGE_SIZE,
                "device-tree",
                BootPageAcceptance::Exclusive,
                device_tree_blob,
            )
            .map_err(Error::ImportDeviceTree)?;

        Some(dtb_start..dtb_end)
    } else {
        None
    };

    Ok(LoadInfo {
        image: load_address..image_file_end,
        entrypoint: load_address,
        dtb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::importer::IgvmParameterType;
    use crate::importer::IsolationConfig;
    use crate::importer::IsolationType;
    use crate::importer::ParameterAreaIndex;
    use crate::importer::StartupMemoryType;
    use std::io::Cursor;

    #[derive(Debug)]
    struct Import {
        page_base: u64,
        page_count: u64,
        tag: String,
        data: Vec<u8>,
    }

    #[derive(Default)]
    struct TestImporter {
        imports: Vec<Import>,
    }

    impl ImageLoad<Aarch64Register> for TestImporter {
        fn isolation_config(&self) -> IsolationConfig {
            IsolationConfig {
                paravisor_present: false,
                isolation_type: IsolationType::None,
                shared_gpa_boundary_bits: None,
            }
        }

        fn create_parameter_area(
            &mut self,
            _page_base: u64,
            _page_count: u32,
            _debug_tag: &str,
        ) -> anyhow::Result<ParameterAreaIndex> {
            unreachable!()
        }

        fn create_parameter_area_with_data(
            &mut self,
            _page_base: u64,
            _page_count: u32,
            _debug_tag: &str,
            _initial_data: &[u8],
        ) -> anyhow::Result<ParameterAreaIndex> {
            unreachable!()
        }

        fn import_parameter(
            &mut self,
            _parameter_area: ParameterAreaIndex,
            _byte_offset: u32,
            _parameter_type: IgvmParameterType,
        ) -> anyhow::Result<()> {
            unreachable!()
        }

        fn import_pages(
            &mut self,
            page_base: u64,
            page_count: u64,
            debug_tag: &str,
            _acceptance: BootPageAcceptance,
            data: &[u8],
        ) -> anyhow::Result<()> {
            self.imports.push(Import {
                page_base,
                page_count,
                tag: debug_tag.to_string(),
                data: data.to_vec(),
            });
            Ok(())
        }

        fn import_vp_register(&mut self, _register: Aarch64Register) -> anyhow::Result<()> {
            unreachable!()
        }

        fn verify_startup_memory_available(
            &mut self,
            _page_base: u64,
            _page_count: u64,
            _memory_type: StartupMemoryType,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn set_vp_context_page(&mut self, _page_base: u64) -> anyhow::Result<()> {
            unreachable!()
        }

        fn relocation_region(
            &mut self,
            _gpa: u64,
            _size_bytes: u64,
            _relocation_alignment: u64,
            _minimum_relocation_gpa: u64,
            _maximum_relocation_gpa: u64,
            _apply_rip_offset: bool,
            _apply_gdtr_offset: bool,
            _vp_index: u16,
        ) -> anyhow::Result<()> {
            unreachable!()
        }

        fn page_table_relocation(
            &mut self,
            _page_table_gpa: u64,
            _size_pages: u64,
            _used_pages: u64,
            _vp_index: u16,
        ) -> anyhow::Result<()> {
            unreachable!()
        }

        fn set_imported_regions_config_page(&mut self, _page_base: u64) {
            unreachable!()
        }
    }

    #[test]
    fn loads_image_and_device_tree() {
        let mut importer = TestImporter::default();
        let mut image = Cursor::new(vec![1, 2, 3]);
        let dtb = [4, 5];

        let info = load_arm64(
            &mut importer,
            &mut image,
            AARCH64_DEFAULT_LOAD_OFFSET,
            Some(&dtb),
            AARCH64_DEFAULT_DTB_OFFSET,
        )
        .unwrap();

        assert_eq!(
            info.image,
            AARCH64_DEFAULT_LOAD_OFFSET..AARCH64_DEFAULT_LOAD_OFFSET + 3
        );
        assert_eq!(info.entrypoint, AARCH64_DEFAULT_LOAD_OFFSET);
        assert_eq!(
            info.dtb,
            Some(AARCH64_DEFAULT_DTB_OFFSET..AARCH64_DEFAULT_DTB_OFFSET + 2)
        );
        assert_eq!(importer.imports.len(), 2);
        assert_eq!(importer.imports[0].page_base, 0x80);
        assert_eq!(importer.imports[0].page_count, 1);
        assert_eq!(importer.imports[0].tag, "raw-kernel");
        assert_eq!(importer.imports[0].data, [1, 2, 3]);
        assert_eq!(
            importer.imports[1].page_base,
            AARCH64_DEFAULT_DTB_OFFSET / HV_PAGE_SIZE
        );
        assert_eq!(importer.imports[1].page_count, 1);
        assert_eq!(importer.imports[1].tag, "device-tree");
        assert_eq!(importer.imports[1].data, dtb);
    }

    #[test]
    fn rejects_empty_or_unaligned_images() {
        let mut importer = TestImporter::default();
        assert!(matches!(
            load_arm64(
                &mut importer,
                &mut Cursor::new(Vec::<u8>::new()),
                AARCH64_DEFAULT_LOAD_OFFSET,
                None,
                AARCH64_DEFAULT_DTB_OFFSET,
            ),
            Err(Error::EmptyImage)
        ));
        assert!(matches!(
            load_arm64(
                &mut importer,
                &mut Cursor::new(vec![1]),
                AARCH64_DEFAULT_LOAD_OFFSET + 1,
                None,
                AARCH64_DEFAULT_DTB_OFFSET,
            ),
            Err(Error::UnalignedLoadAddress(_))
        ));
    }
}
