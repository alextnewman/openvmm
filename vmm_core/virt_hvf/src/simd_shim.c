// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <Hypervisor/hv_vcpu.h>
#include <stdint.h>
#include <string.h>

#if defined(__aarch64__)

hv_return_t
openvmm_hv_vcpu_get_simd_fp_reg(hv_vcpu_t vcpu, uint32_t reg,
                                uint8_t value[16])
{
    hv_simd_fp_uchar16_t simd_value;
    hv_return_t result =
        hv_vcpu_get_simd_fp_reg(vcpu, (hv_simd_fp_reg_t)reg, &simd_value);

    if (result == HV_SUCCESS) {
        memcpy(value, &simd_value, sizeof(simd_value));
    }
    return result;
}

hv_return_t
openvmm_hv_vcpu_set_simd_fp_reg(hv_vcpu_t vcpu, uint32_t reg,
                                const uint8_t value[16])
{
    hv_simd_fp_uchar16_t simd_value;

    memcpy(&simd_value, value, sizeof(simd_value));
    return hv_vcpu_set_simd_fp_reg(vcpu, (hv_simd_fp_reg_t)reg, simd_value);
}

#endif
