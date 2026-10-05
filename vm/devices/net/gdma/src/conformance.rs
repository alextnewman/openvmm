// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deterministic device controls, deliberately separate from the examiner.

use gdma_defs::GdmaRequestType;
use gdma_defs::GdmaRespHdr;
use gdma_defs::bnic::ManaCommandCode;
use gdma_resources::ConformanceScenario;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

pub(crate) struct DeviceScenario {
    scenario: Option<ConformanceScenario>,
    rejected_stat: AtomicBool,
    corrupted_reply: AtomicBool,
}

impl DeviceScenario {
    pub fn new(scenario: Option<ConformanceScenario>) -> Self {
        Self {
            scenario,
            rejected_stat: AtomicBool::new(false),
            corrupted_reply: AtomicBool::new(false),
        }
    }

    pub fn reject_optional_stat(&self, code: u32) -> bool {
        self.scenario == Some(ConformanceScenario::ShortStatError)
            && matches!(
                ManaCommandCode(code),
                ManaCommandCode::MANA_QUERY_STATS | ManaCommandCode::MANA_QUERY_PHY_STAT
            )
            && !self.rejected_stat.swap(true, Ordering::Relaxed)
    }

    pub fn alter_response(&self, code: u32, response: &mut GdmaRespHdr) {
        if self.scenario == Some(ConformanceScenario::BadCorrelation)
            && code == GdmaRequestType::GDMA_QUERY_MAX_RESOURCES.0
            && response.status == 0
            && !self.corrupted_reply.swap(true, Ordering::Relaxed)
        {
            response.response.hwc_msg_id = response.response.hwc_msg_id.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gdma_defs::GdmaMsgHdr;
    use gdma_defs::HWC_DEV_ID;
    use test_with_tracing::test;

    #[test]
    fn optional_rejection_is_once_and_never_changes_ownership() {
        let scenario = DeviceScenario::new(Some(ConformanceScenario::ShortStatError));
        assert!(!scenario.reject_optional_stat(ManaCommandCode::MANA_CREATE_WQ_OBJ.0));
        assert!(scenario.reject_optional_stat(ManaCommandCode::MANA_QUERY_PHY_STAT.0));
        assert!(!scenario.reject_optional_stat(ManaCommandCode::MANA_QUERY_STATS.0));
    }

    #[test]
    fn correlation_fault_is_once_and_only_on_a_successful_read_only_reply() {
        let scenario = DeviceScenario::new(Some(ConformanceScenario::BadCorrelation));
        let mut response = GdmaRespHdr {
            response: GdmaMsgHdr {
                hwc_msg_id: u16::MAX,
                ..zerocopy::FromZeros::new_zeroed()
            },
            dev_id: HWC_DEV_ID,
            activity_id: 73,
            status: 1,
            reserved: 0,
        };
        scenario.alter_response(GdmaRequestType::GDMA_QUERY_MAX_RESOURCES.0, &mut response);
        assert_eq!(response.response.hwc_msg_id, u16::MAX);
        response.status = 0;
        scenario.alter_response(GdmaRequestType::GDMA_CREATE_DMA_REGION.0, &mut response);
        assert_eq!(response.response.hwc_msg_id, u16::MAX);
        scenario.alter_response(GdmaRequestType::GDMA_QUERY_MAX_RESOURCES.0, &mut response);
        assert_eq!(response.response.hwc_msg_id, 0);
        assert_eq!(response.activity_id, 73);
        scenario.alter_response(GdmaRequestType::GDMA_QUERY_MAX_RESOURCES.0, &mut response);
        assert_eq!(response.response.hwc_msg_id, 0);
    }
}
