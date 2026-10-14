// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exports [`IoRanges`], which models a linear address-space with certain
//! regions "claimed" by [`ChipsetDevice`]s.
//!
//! - e.g: `IoRanges<u64>` can be used to model 64-bit MMIO.
//! - e.g: `IoRanges<u16>` can be used to model 16-bit x86 port IO.

use address_filter::AddressFilter;
use address_filter::RangeKey;
use chipset_device::ChipsetDevice;
use closeable_mutex::CloseableMutex;
use inspect::Inspect;
use inspect_counters::SharedCounter;
use parking_lot::RwLock;
use range_map_vec::RangeMap;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::Weak;

struct IoRangesInner<T> {
    map: RangeMap<T, RangeEntry>,
    fallback_map: RangeMap<T, RangeEntry>,
    trace_on: AddressFilter<T>,
    break_on: AddressFilter<T>,
    // Starts off a `Some(Vec::new())`, and then set to `None` as part of
    // Chipset finalization
    static_registration_conflicts: Option<Vec<IoRangeConflict<T>>>,
    fallback_device: Option<Arc<CloseableMutex<dyn ChipsetDevice>>>,
}

#[derive(Debug, Clone)]
pub struct IoRangeConflict<T> {
    existing_dev_region: (Arc<str>, Arc<str>, RangeInclusive<T>),
    conflict_dev_region: (Arc<str>, Arc<str>, RangeInclusive<T>),
}

impl<T> std::error::Error for IoRangeConflict<T> where T: std::fmt::LowerHex + core::fmt::Debug {}
impl<T> std::fmt::Display for IoRangeConflict<T>
where
    T: std::fmt::LowerHex + core::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}:{:#x?} conflicts with existing {}/{}:{:#x?}",
            self.conflict_dev_region.0,
            self.conflict_dev_region.1,
            self.conflict_dev_region.2,
            self.existing_dev_region.0,
            self.existing_dev_region.1,
            self.existing_dev_region.2,
        )
    }
}

#[derive(Inspect)]
struct RangeEntry {
    region_name: Arc<str>,
    dev_name: Arc<str>,
    #[inspect(rename = "device_is_init", with = "|x| x.upgrade().is_some()")]
    dev: Weak<CloseableMutex<dyn ChipsetDevice>>,
    read_count: SharedCounter,
    write_count: SharedCounter,
}

#[derive(Clone)]
pub struct IoRanges<T> {
    inner: Arc<RwLock<IoRangesInner<T>>>,
}

impl<T: RangeKey> IoRanges<T> {
    pub fn new(
        trace_on_unknown: bool,
        fallback_device: Option<Arc<CloseableMutex<dyn ChipsetDevice>>>,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(IoRangesInner {
                map: RangeMap::new(),
                fallback_map: RangeMap::new(),
                trace_on: AddressFilter::new(trace_on_unknown),
                break_on: AddressFilter::new(false),
                static_registration_conflicts: Some(Vec::new()),
                fallback_device,
            })),
        }
    }

    pub fn register(
        &self,
        start: T,
        end: T,
        region_name: Arc<str>,
        dev: Weak<CloseableMutex<dyn ChipsetDevice>>,
        dev_name: Arc<str>,
    ) -> Result<(), IoRangeConflict<T>> {
        self.register_inner(start, end, region_name, dev, dev_name, false)
    }

    pub fn register_fallback(
        &self,
        start: T,
        end: T,
        region_name: Arc<str>,
        dev: Weak<CloseableMutex<dyn ChipsetDevice>>,
        dev_name: Arc<str>,
    ) -> Result<(), IoRangeConflict<T>> {
        self.register_inner(start, end, region_name, dev, dev_name, true)
    }

    fn register_inner(
        &self,
        start: T,
        end: T,
        region_name: Arc<str>,
        dev: Weak<CloseableMutex<dyn ChipsetDevice>>,
        dev_name: Arc<str>,
        fallback: bool,
    ) -> Result<(), IoRangeConflict<T>> {
        let mut inner = self.inner.write();
        let map = if fallback {
            &mut inner.fallback_map
        } else {
            &mut inner.map
        };
        match map.entry(start..=end) {
            range_map_vec::Entry::Vacant(entry) => {
                entry.insert(RangeEntry {
                    region_name,
                    dev,
                    dev_name,
                    read_count: Default::default(),
                    write_count: Default::default(),
                });
                Ok(())
            }
            range_map_vec::Entry::Overlapping(entry) => {
                let existing_dev_region = {
                    let (start, end, entry) = entry.get();
                    (
                        entry.dev_name.clone(),
                        entry.region_name.clone(),
                        *start..=*end,
                    )
                };
                let conflict = IoRangeConflict {
                    existing_dev_region,
                    conflict_dev_region: (dev_name, region_name, start..=end),
                };

                if let Some(v) = inner.static_registration_conflicts.as_mut() {
                    v.push(conflict.clone())
                }

                Err(conflict)
            }
        }
    }

    pub fn revoke(&self, start: T) {
        let mut inner = self.inner.write();
        inner.map.remove(&start);
    }

    pub fn revoke_fallback(&self, start: T) {
        self.inner.write().fallback_map.remove(&start);
    }

    pub fn lookup(&self, addr: T, is_read: bool) -> LookupResult {
        self.lookup_range(addr, Some(addr), is_read)
    }

    pub fn lookup_range(&self, addr: T, end: Option<T>, is_read: bool) -> LookupResult {
        let end = end.filter(|end| *end >= addr);
        static UNKNOWN_DEVICE: OnceLock<Arc<CloseableMutex<dyn ChipsetDevice>>> = OnceLock::new();
        static UNKNOWN_DEVICE_NAME: OnceLock<Arc<str>> = OnceLock::new();
        static UNKNOWN_RANGE: OnceLock<Arc<str>> = OnceLock::new();

        let inner = self.inner.read();
        let resolved = inner
            .map
            .get(&addr)
            .filter(|_| end.is_some())
            .and_then(|entry| entry.dev.upgrade().map(|dev| (entry, dev)))
            .or_else(|| {
                let end = end?;
                let entry = inner.fallback_map.get(&addr)?;
                if !inner
                    .fallback_map
                    .get(&end)
                    .is_some_and(|last| std::ptr::eq(entry, last))
                {
                    return None;
                }
                // A fallback must not consume bytes belonging to a more
                // specific intercept later in the same access.
                if inner.map.iter().any(|(range, entry)| {
                    *range.start() <= end && addr <= *range.end() && entry.dev.upgrade().is_some()
                }) {
                    return None;
                }
                entry.dev.upgrade().map(|dev| (entry, dev))
            });
        let entry = resolved.as_ref().map(|(entry, _)| *entry);
        if let Some(entry) = entry {
            if is_read {
                entry.read_count.increment()
            } else {
                entry.write_count.increment()
            }
        }

        let (dev, dev_name) =
            resolved
                .map(|(entry, dev)| (dev, entry.dev_name.clone()))
                .unwrap_or_else(|| {
                    (
                        inner.fallback_device.clone().unwrap_or_else(|| {
                            UNKNOWN_DEVICE
                        .get_or_init(|| {
                            Arc::new(CloseableMutex::new(missing_dev::MissingDev::from_manifest(
                                missing_dev::MissingDevManifest::new(),
                                &mut chipset_device::mmio::ExternallyManagedMmioIntercepts,
                                &mut chipset_device::pio::ExternallyManagedPortIoIntercepts,
                            )))
                        })
                        .clone()
                        }),
                        UNKNOWN_DEVICE_NAME
                            .get_or_init(|| "<unknown>".into())
                            .clone(),
                    )
                });

        let trace = inner.trace_on.filtered(&addr, entry.is_some());
        let trace = trace.then(|| {
            entry.map_or_else(
                || UNKNOWN_RANGE.get_or_init(|| "<unknown>".into()).clone(),
                |e| e.region_name.clone(),
            )
        });
        let debug_break = inner.break_on.filtered(&addr, entry.is_some());
        LookupResult {
            dev,
            dev_name,
            trace,
            debug_break,
        }
    }

    pub fn take_static_registration_conflicts(&mut self) -> Vec<IoRangeConflict<T>> {
        self.inner
            .write()
            .static_registration_conflicts
            .take()
            .expect("must only be called once")
    }

    pub fn is_occupied(&self, addr: T) -> bool {
        let inner = self.inner.read();
        inner.map.contains(&addr) || inner.fallback_map.contains(&addr)
    }
}

pub struct LookupResult {
    pub dev: Arc<CloseableMutex<dyn ChipsetDevice>>,
    pub dev_name: Arc<str>,
    pub trace: Option<Arc<str>>,
    pub debug_break: bool,
}

impl<T: RangeKey> Inspect for IoRanges<T> {
    fn inspect(&self, req: inspect::Request<'_>) {
        let mut resp = req.respond();
        let mut inner = self.inner.write();
        resp.field_mut("trace_on", &mut inner.trace_on)
            .field_mut("break_on", &mut inner.break_on);
        for (range, entry) in inner.map.iter() {
            resp.field(&format!("{:#x}-{:#x}", range.start(), range.end()), entry);
        }
        for (range, entry) in inner.fallback_map.iter() {
            resp.field(
                &format!("fallback/{:#x}-{:#x}", range.start(), range.end()),
                entry,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[derive(inspect::InspectMut)]
    struct TestDevice;
    impl ChipsetDevice for TestDevice {}

    fn device() -> Arc<CloseableMutex<dyn ChipsetDevice>> {
        Arc::new(CloseableMutex::new(TestDevice))
    }

    #[test]
    fn bar_intercepts_override_fallback_without_replacing_it() {
        let ranges = IoRanges::new(false, None);
        let fabric = device();
        let endpoint = device();
        ranges
            .register_fallback(
                0x100u64,
                0x1ff,
                "aperture".into(),
                Arc::downgrade(&fabric),
                "fabric".into(),
            )
            .unwrap();
        assert!(ranges.is_occupied(0x180));
        ranges
            .register(
                0x180,
                0x18f,
                "bar".into(),
                Arc::downgrade(&endpoint),
                "endpoint".into(),
            )
            .unwrap();
        assert!(Arc::ptr_eq(&ranges.lookup(0x184, true).dev, &endpoint));
        assert!(Arc::ptr_eq(&ranges.lookup(0x170, true).dev, &fabric));
        ranges.revoke(0x180);
        assert!(Arc::ptr_eq(&ranges.lookup(0x184, false).dev, &fabric));
        assert_eq!(ranges.lookup(0x200, true).dev_name.as_ref(), "<unknown>");
        ranges.revoke_fallback(0x100);
        assert_eq!(ranges.lookup(0x184, true).dev_name.as_ref(), "<unknown>");
        assert!(!ranges.is_occupied(0x184));
    }

    #[test]
    fn expired_regular_target_does_not_hide_live_fallback() {
        let ranges = IoRanges::new(false, None);
        let fabric = device();
        let endpoint = device();
        ranges
            .register_fallback(
                0x100u64,
                0x1ff,
                "aperture".into(),
                Arc::downgrade(&fabric),
                "fabric".into(),
            )
            .unwrap();
        ranges
            .register(
                0x180,
                0x18f,
                "bar".into(),
                Arc::downgrade(&endpoint),
                "endpoint".into(),
            )
            .unwrap();
        drop(endpoint);
        assert!(Arc::ptr_eq(&ranges.lookup(0x184, true).dev, &fabric));
    }

    #[test]
    fn fallback_conflicts_are_detected_within_the_same_priority() {
        let ranges = IoRanges::new(false, None);
        let first = device();
        let second = device();
        ranges
            .register_fallback(
                0x100u64,
                0x1ff,
                "first".into(),
                Arc::downgrade(&first),
                "first".into(),
            )
            .unwrap();
        assert!(
            ranges
                .register_fallback(
                    0x180,
                    0x2ff,
                    "second".into(),
                    Arc::downgrade(&second),
                    "second".into()
                )
                .is_err()
        );
        assert!(Arc::ptr_eq(&ranges.lookup(0x190, true).dev, &first));
    }

    #[test]
    fn fallback_does_not_swallow_a_partial_higher_priority_mapping() {
        let ranges = IoRanges::new(false, None);
        let fabric = device();
        let endpoint = device();
        ranges
            .register_fallback(
                0x100u64,
                0x1ff,
                "aperture".into(),
                Arc::downgrade(&fabric),
                "fabric".into(),
            )
            .unwrap();
        ranges
            .register(
                0x184,
                0x187,
                "register".into(),
                Arc::downgrade(&endpoint),
                "endpoint".into(),
            )
            .unwrap();
        assert!(Arc::ptr_eq(
            &ranges.lookup_range(0x180, Some(0x183), true).dev,
            &fabric
        ));
        assert_eq!(
            ranges
                .lookup_range(0x180, Some(0x187), true)
                .dev_name
                .as_ref(),
            "<unknown>"
        );
        assert_eq!(
            ranges
                .lookup_range(0x180, Some(0x18f), false)
                .dev_name
                .as_ref(),
            "<unknown>"
        );
        assert_eq!(
            ranges
                .lookup_range(0x1fc, Some(0x203), true)
                .dev_name
                .as_ref(),
            "<unknown>"
        );
        assert_eq!(
            ranges.lookup_range(u64::MAX, None, true).dev_name.as_ref(),
            "<unknown>"
        );
    }
}
