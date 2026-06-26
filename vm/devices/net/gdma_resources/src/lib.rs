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

/// A resource handle to a GDMA device.
#[derive(MeshPayload)]
pub struct GdmaDeviceHandle {
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
