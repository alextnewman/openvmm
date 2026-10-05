// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resource definitions for MANA/GDMA devices.

#![forbid(unsafe_code)]

use mesh::MeshPayload;
use net_backend_resources::mac_address::MacAddress;
use vm_resource::Resource;
use vm_resource::ResourceId;
use vm_resource::kind::NetEndpointHandleKind;
use vm_resource::kind::PciDeviceHandleKind;

/// An explicit device behavior used by a two-sided conformance experiment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, MeshPayload)]
pub enum ConformanceScenario {
    /// Unmodified device behavior.
    Baseline,
    /// Advertise and enforce four event queues, including the HWC queue.
    ConstrainedEqs,
    /// Reject one optional statistics query with a legal header-only error.
    ShortStatError,
    /// Corrupt one read-only resource-query reply's correlation cookie.
    BadCorrelation,
}

impl ConformanceScenario {
    /// The stable CLI and evidence name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::ConstrainedEqs => "constrained-eqs",
            Self::ShortStatError => "short-stat-error",
            Self::BadCorrelation => "bad-correlation",
        }
    }

    /// Number of EQs actually available in this device scenario.
    pub fn max_eqs(self) -> u32 {
        match self {
            Self::ConstrainedEqs => 4,
            _ => 64,
        }
    }
}

impl std::fmt::Display for ConformanceScenario {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ConformanceScenario {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "baseline" => Ok(Self::Baseline),
            "constrained-eqs" => Ok(Self::ConstrainedEqs),
            "short-stat-error" => Ok(Self::ShortStatError),
            "bad-correlation" => Ok(Self::BadCorrelation),
            _ => Err("expected baseline, constrained-eqs, short-stat-error, or bad-correlation"),
        }
    }
}

/// A resource handle to a GDMA device.
#[derive(MeshPayload)]
pub struct GdmaDeviceHandle {
    /// Enable passive protocol findings and per-rule observation coverage.
    pub protocol_monitor: bool,
    /// Opt-in device behavior; independent of passive contract interpretation.
    pub conformance_scenario: Option<ConformanceScenario>,
    /// The vports to instantiate on the NIC.
    pub vports: Vec<VportDefinition>,
    /// Present the device as a bare-metal physical function (PCI id
    /// `1414:00b9`) reporting `bm_hostmode`, to exercise the Linux driver's
    /// bare-metal-host code paths instead of the SR-IOV VF paths.
    pub bm_hostmode: bool,
    /// Expose the PF capability register block in BAR0, advertising the
    /// device's resource limits to a physical-function driver.
    pub pf_caps: bool,
}

impl ResourceId<PciDeviceHandleKind> for GdmaDeviceHandle {
    const ID: &'static str = "gdma";
}

/// A basic NIC vport definition.
#[derive(MeshPayload)]
pub struct VportDefinition {
    /// The vport's MAC address.
    pub mac_address: MacAddress,
    /// The backend network endpoint for the vport.
    pub endpoint: Resource<NetEndpointHandleKind>,
}
