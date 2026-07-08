// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use gdma_defs::PAGE_SIZE32;
use gdma_defs::PAGE_SIZE64;
use guestmem::ranges::PagedRange;

#[derive(Clone)]
pub struct DmaRegion {
    /// The list of 4KB guest page numbers (GPNs).
    gpns: Vec<u64>,
    /// The starting byte offset within the first guest page.
    start: usize,
    /// The total length of the region.
    len: usize,
}

impl DmaRegion {
    pub fn new(mut gpas: Vec<u64>, start: u32, len: u64) -> anyhow::Result<Self> {
        for gpa in &mut gpas {
            if *gpa % PAGE_SIZE64 != 0 {
                anyhow::bail!("page address is not 4KB aligned");
            }
            *gpa /= PAGE_SIZE64;
        }
        if len == 0 {
            anyhow::bail!("empty region");
        }
        if start >= PAGE_SIZE32 {
            anyhow::bail!("start offset too large");
        }
        let cap = gpas.len() as u64 * PAGE_SIZE64;
        if cap < len || cap - len < start as u64 {
            anyhow::bail!("not enough pages");
        }
        Ok(Self {
            gpns: gpas,
            start: start as usize,
            len: len as usize,
        })
    }

    pub fn double(&mut self) {
        assert!(self.is_aligned_to(PAGE_SIZE64 as usize));
        self.gpns.extend_from_within(..);
        self.len *= 2;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_aligned_to(&self, align: usize) -> bool {
        assert!(align <= PAGE_SIZE64 as usize);
        (self.start | self.len).is_multiple_of(align)
    }

    pub fn range(&self) -> PagedRange<'_> {
        PagedRange::new(self.start, self.len, &self.gpns).unwrap()
    }
}

/// Accumulates the page list of a DMA region that the guest delivers across
/// several HW channel messages: an initial `GDMA_CREATE_DMA_REGION` carrying the
/// first `page_addr_list_len` page addresses, followed by one or more
/// `GDMA_DMA_REGION_ADD_PAGES` messages supplying the remainder. The region is
/// usable only once every page has arrived ([`DmaRegionBuilder::is_complete`]),
/// at which point [`DmaRegionBuilder::build`] validates the assembled list and
/// produces a [`DmaRegion`].
pub struct DmaRegionBuilder {
    /// Raw guest page byte addresses received so far (validated on build).
    page_addrs: Vec<u64>,
    /// The byte offset within the first page.
    offset_in_page: u32,
    /// The total length of the region in bytes.
    length: u64,
    /// The total number of pages the completed region must contain.
    page_count: usize,
}

impl DmaRegionBuilder {
    /// Starts a region from the first chunk of page addresses and the declared
    /// total `page_count`. `first_pages` may already complete the region (when
    /// the guest sent the whole list in one message).
    pub fn new(
        first_pages: Vec<u64>,
        offset_in_page: u32,
        length: u64,
        page_count: u32,
    ) -> anyhow::Result<Self> {
        let page_count = page_count as usize;
        if page_count == 0 {
            anyhow::bail!("region has no pages");
        }
        if first_pages.len() > page_count {
            anyhow::bail!("initial page list longer than page count");
        }
        Ok(Self {
            page_addrs: first_pages,
            offset_in_page,
            length,
            page_count,
        })
    }

    /// Appends a chunk of page addresses from a `GDMA_DMA_REGION_ADD_PAGES`
    /// message. Fails if the chunk is empty or would overflow the declared page
    /// count.
    pub fn add_pages(&mut self, pages: &[u64]) -> anyhow::Result<()> {
        if pages.is_empty() {
            anyhow::bail!("add pages with empty page list");
        }
        if self.page_addrs.len() + pages.len() > self.page_count {
            anyhow::bail!("added pages exceed region page count");
        }
        self.page_addrs.extend_from_slice(pages);
        Ok(())
    }

    /// Whether every page of the region has been received.
    pub fn is_complete(&self) -> bool {
        self.page_addrs.len() == self.page_count
    }

    /// Validates the assembled page list and produces the finished region. Fails
    /// if the region is not yet complete.
    pub fn build(&self) -> anyhow::Result<DmaRegion> {
        if !self.is_complete() {
            anyhow::bail!("region page list incomplete");
        }
        DmaRegion::new(self.page_addrs.clone(), self.offset_in_page, self.length)
    }
}

#[cfg(test)]
mod tests {
    use super::DmaRegionBuilder;
    use gdma_defs::PAGE_SIZE64;

    #[test]
    fn builder_assembles_multi_message_region() {
        let page = |i: u64| i * PAGE_SIZE64;
        let mut builder = DmaRegionBuilder::new(vec![page(10)], 0, 3 * PAGE_SIZE64, 3).unwrap();
        assert!(!builder.is_complete());
        assert!(builder.build().is_err());

        builder.add_pages(&[page(11)]).unwrap();
        assert!(!builder.is_complete());

        builder.add_pages(&[page(12)]).unwrap();
        assert!(builder.is_complete());

        let region = builder.build().unwrap();
        assert_eq!(region.len(), (3 * PAGE_SIZE64) as usize);
        assert_eq!(region.range().gpns(), &[10, 11, 12]);
    }

    #[test]
    fn builder_rejects_overflow_and_misorder() {
        let page = |i: u64| i * PAGE_SIZE64;
        // Initial chunk larger than the declared total.
        assert!(DmaRegionBuilder::new(vec![page(1), page(2)], 0, PAGE_SIZE64, 1).is_err());

        // Adding more pages than the region declares.
        let mut builder = DmaRegionBuilder::new(vec![page(1)], 0, 2 * PAGE_SIZE64, 2).unwrap();
        assert!(builder.add_pages(&[page(2), page(3)]).is_err());
        // The valid remainder still completes the region.
        builder.add_pages(&[page(2)]).unwrap();
        assert!(builder.is_complete());
    }
}
