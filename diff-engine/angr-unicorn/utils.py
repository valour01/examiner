import struct


def bin2bytes(num: str, mode: str):
    if mode == 'thumb':
        return struct.pack("<H", int(num[:16], 2)) + struct.pack("<H", int(num[16:], 2))
    else:
        return struct.pack("<L", int(num, 2))


def bytes2hex(b: bytes, mode: str):
    if mode == 'thumb':
        return (b[:2][::-1] + b[2:][::-1]).hex()
    else:
        return b[::-1].hex()


def hex2bytes(num: str, mode: str):
    if mode == 'thumb':
        return struct.pack("<H", int(num[:4], 16)) + struct.pack("<H", int(num[4:], 16))
    else:
        return struct.pack("<L", int(num, 16))


def bytes2bin(b: bytes, mode: str):
    return bin(int(bytes2hex(b, mode), 16))[2:]


def hex2bin(num: str):
    return bin(int(num, base=16))[2:].rjust(32, '0')


def encoding2instname(encoding, mode):
    if mode == 'arm64':
        return encoding.rsplit("_", 1)[1]
    else:
        return encoding.rsplit("_", 2)[0].split("_", 1)[1]


COPROC_INSTS = {
    "aarch32_LDC_i_T1A1_A",
    "aarch32_MRC_T1A1_A",
    "aarch32_MCR_T1A1_A",
    "aarch32_MRRC_T1A1_A",
    "aarch32_MCRR_T1A1_A",
}

VECTOR_INSTS = {
    "aarch32_VABA_T1A1_A",
    "aarch32_VABA_T2A2_A",
    "aarch32_VABD_i_T1A1_A",
    "aarch32_VABD_i_T2A2_A",
    "aarch32_VADDHN_T1A1_A",
    "aarch32_VADDL_T1A1_A",
    "aarch32_VADD_i_T1A1_A",
    "aarch32_VBIC_i_T1A1_A",
    "aarch32_VBIC_i_T2A2_A",
    "aarch32_VBIF_T1A1_A",
    "aarch32_VCEQ_r_T1A1_A",
    "aarch32_VCGE_r_T1A1_A",
    "aarch32_VCGT_r_T1A1_A",
    "aarch32_VCLS_T1A1_A",
    "aarch32_VCLZ_T1A1_A",
    "aarch32_VCNT_T1A1_A",
    "aarch32_VCVTA_asimd_T1_A",
    "aarch32_VCVTA_vfp_T1_A",
    "aarch32_VCVT_xs_T1_A",
    "aarch32_VEOR_T1A1_A",
    "aarch32_VEXT_T1A1_A",
    "aarch32_VHADD_T1A1_A",
    "aarch32_VMAXNM_T2_A",
    "aarch32_VMAX_i_T1A1_A",
    "aarch32_VMLA_i_T1A1_A",
    "aarch32_VMLA_s_T2A2_A",
    "aarch32_VMOV_i_T1A1_A",
    "aarch32_VMOV_i_T3A3_A",
    "aarch32_VMUL_i_T1A1_A",
    "aarch32_VMUL_i_T2_A",
    "aarch32_VMUL_s_T2A2_A",
    "aarch32_VMVN_i_T2A2_A",
    "aarch32_VMVN_r_T1A1_A",
    "aarch32_VORN_r_T1A1_A",
    "aarch32_VORR_i_T1A1_A",
    "aarch32_VORR_i_T2A2_A",
    "aarch32_VPADD_i_T1A1_A",
    "aarch32_VQADD_T1A1_A",
    "aarch32_VQDMLAL_T1A1_A",
    "aarch32_VQDMLAL_T2A2_A",
    "aarch32_VQDMULH_T1A1_A",
    "aarch32_VQDMULH_T2A2_A",
    "aarch32_VQDMULL_T1A1_A",
    "aarch32_VQDMULL_T2A2_A",
    "aarch32_VQRDMLAH_T1_A",
    "aarch32_VQRDMLAH_T2_A",
    "aarch32_VQRDMLSH_T2_A",
    "aarch32_VQRDMULH_T1A1_A",
    "aarch32_VQRDMULH_T2A2_A",
    "aarch32_VQRSHL_T1A1_A",
    "aarch32_VQSHL_i_T1A1_A",
    "aarch32_VQSHL_r_T1A1_A",
    "aarch32_VQSHRN_T1A1_A",
    "aarch32_VQSUB_T1A1_A",
    "aarch32_VRADDHN_T1A1_A",
    "aarch32_VREV16_T1A1_A",
    "aarch32_VRHADD_T1A1_A",
    "aarch32_VRINTA_vfp_T1_A",
    "aarch32_VRINTX_asimd_T1_A",
    "aarch32_VRINTZ_asimd_T1_A",
    "aarch32_VRSHL_T1A1_A",
    "aarch32_VRSHRN_T1A1_A",
    "aarch32_VRSHR_T1A1_A",
    "aarch32_VRSUBHN_T1A1_A",
    "aarch32_VSEL_T1_A",
    "aarch32_VSHL_i_T1A1_A",
    "aarch32_VSHL_r_T1A1_A",
    "aarch32_VSHRN_T1A1_A",
    "aarch32_VSHR_T1A1_A",
    "aarch32_VSLI_T1A1_A",
    "aarch32_VSRA_T1A1_A",
    "aarch32_VSRI_T1A1_A",
    "aarch32_VSUBL_T1A1_A",
    "aarch32_VSUB_i_T1A1_A",
    "aarch32_VSWP_T1A1_A",
    "aarch32_VTRN_T1A1_A",
    "aarch32_VTST_T1A1_A",
    "aarch32_VUZP_T1A1_A",
    "aarch32_VZIP_T1A1_A",
    "aarch32_VMLA_i_T2A2_A",
    "aarch32_VRSRA_T1A1_A",
    "aarch32_VPMAX_i_T1A1_A",
    "aarch32_VSUBHN_T1A1_A",
    "aarch32_VBIC_r_T1A1_A",
    "aarch32_VMAXNM_T1_A",
    "aarch32_VAND_r_T1A1_A",
    "aarch32_VDUP_s_T1A1_A",
    "aarch32_VCVTB_T1A1_A",
    "aarch32_VQNEG_T1A1_A",
    "aarch32_VORR_r_T1A1_A",
    "aarch32_VPADDL_T1A1_A",
    "aarch32_VPADAL_T1A1_A",
    "aarch32_VMOVX_T1_A",
    "aarch32_VQRSHRN_T1A1_A",
    "aarch32_VSHLL_T2A2_A",
    "aarch32_VQRDMLSH_T1_A",
    "aarch32_VRINTA_asimd_T1_A",
    "aarch32_VMVN_i_T1A1_A",
    "aarch32_VMOVN_T1A1_A",
    "aarch32_VQABS_T1A1_A",
    "aarch32_VMVN_i_T3A3_A",
    "aarch32_VCVT_hs_T1A1_A",
    "aarch32_VQMOVN_T1A1_A",
    "aarch32_VMOVL_T1A1_A",
    "aarch32_VSHLL_T1A1_A",
    "aarch32_VINS_T1_A",
    "aarch32_VMOV_i_T5A5_A",
    "aarch32_VMOV_i_T4A4_A",
    "aarch32_VRSRA_T1A1_A",
    "aarch32_VORR_r_T1A1_A",
    "aarch32_VMVN_i_T1A1_A",
    "aarch32_VAND_r_T1A1_A",
    "aarch32_VDUP_s_T1A1_A",
    "aarch32_VAND_r_T1A1_A",
    "aarch32_VBIC_r_T1A1_A",
    "aarch32_VMOV_r_T2A2_A",
    "aarch32_VSEL_A1_A",
    "aarch32_VSUB_f_A1_A",
    "aarch32_VMUL_f_A1_A",
    "aarch32_VMAXNM_A2_A",
    "aarch32_VABD_f_A1_A",
    "aarch32_VADD_f_A1_A",
    "aarch32_VABS_A1_A",
    "aarch32_VCVTA_asimd_A1_A",
    "aarch32_VRINTA_vfp_A1_A",
    "aarch32_VRINTX_asimd_A1_A",
    "aarch32_VMOVX_A1_A",
    "aarch32_VRINTA_asimd_A1_A",
    "aarch32_VCVTA_vfp_A1_A",
    "aarch32_VINS_A1_A",
    "aarch32_VRINTZ_asimd_A1_A",
    "aarch32_VCVT_xs_A1_A",
    "aarch32_VMLA_s_A1_A",
    "aarch32_VFMA_A1_A",
    "aarch32_VMUL_s_A1_A",
    "aarch32_VRECPS_A1_A",
    "aarch32_VCEQ_i_A1_A",
    "aarch32_VMLA_f_A1_A",
    "aarch32_VMAX_f_A1_A",
    "aarch32_VRSQRTS_A1_A",
    "aarch32_VMUL_i_A2_A",
    "aarch32_VPMAX_f_A1_A",
    "aarch32_VCGE_r_A2_A",
    "aarch32_VCGT_i_A1_A",
    "aarch32_VACGE_A1_A",
    "aarch32_VCVT_ds_T1A1_A",
    "aarch32_VCLT_i_A1_A",
    "aarch32_VCGT_r_A2_A",
    "aarch32_VCEQ_r_A2_A",
    "aarch32_VPADD_f_A1_A",
    "aarch32_VCVT_is_A1_A",
    "aarch32_VCGE_i_A1_A",
    "aarch32_VRSQRTE_A1_A",
    "aarch32_VRECPE_A1_A",
    "aarch32_VNEG_A1_A",
    "aarch32_VCLE_i_A1_A",
    "aarch32_VQRDMLAH_A2_A",
    "aarch32_VQRDMLSH_A2_A",
}


SPECIAL_INSTS = {
    "aarch32_SRS_A1_AS",
    "aarch32_SRS_T1_AS",
    "aarch32_SRS_T2_AS",
    #
    "aarch32_PLD_i_A1_A",
    "aarch32_PLD_i_T1_A",
    "aarch32_PLD_i_T2_A",
    "aarch32_PLD_l_T1_A",
    "aarch32_PLI_i_T1_A",
    "aarch32_PLI_i_T2_A",
    "aarch32_PLI_i_T3_A",
    #
    "aarch32_BKPT_A1_A",
    "aarch32_BKPT_T1_A",
    #
    "aarch32_SVC_A1_A",
    "aarch32_SVC_T1_A",
    "aarch32_SMC_T1_AS",
    #
    "aarch32_DSB_A1_A",
    "aarch32_DSB_T1_A",
    "aarch32_ISB_A1_A",
    "aarch32_ISB_T1_A",
    "aarch32_DMB_A1_A",
    "aarch32_ESB_T1_A",
    #
    "aarch32_MSR_i_A1_AS",
    #
    "aarch32_SETEND_A1_A",
    "aarch32_SETEND_T1_A",
    "aarch32_SETPAN_T1_A",
    #
    "aarch32_HLT_A1_A",
    "aarch32_HLT_T1_A",
    #
    "aarch32_HVC_A1_A",
    "aarch32_HVC_T1_A",
    #
    "aarch32_AESIMC_T1_A",
    "aarch32_AESD_T1_A",
    "aarch32_AESE_T1_A",
    "aarch32_AESMC_T1_A",
    #
    "aarch32_DCPS_T1_A",
    #
    "aarch32_UDF_T1_A",
    "aarch32_UDF_T2_A",
    "aarch32_WFI_T1_A",
    "aarch32_WFI_T2_A",
    #
    "aarch32_CLREX_T1_A",
    "aarch32_WFE_T1_A",
    "aarch32_WFE_T2_A",
    "aarch32_SEV_T1_A",
    "aarch32_SEV_T2_A",
    "aarch32_SEVL_T1_A",
    "aarch32_SEVL_T2_A",
    "aarch32_YIELD_T1_A",
    "aarch32_YIELD_T2_A",
    "aarch32_DBG_T1_A",
    "aarch32_SXTB_T1_A",

}

SHA_INSTS = {
    "aarch32_SHA1SU0_T1_A",
    "aarch32_SHA1C_T1_A",
    "aarch32_SHA1P_T1_A",
    "aarch32_SHA256H2_T1_A",
    "aarch32_SHA1SU1_T1_A",
    "aarch32_SHA256SU1_T1_A",
    "aarch32_SHA256H_T1_A",
    "aarch32_SHA1H_T1_A",
    "aarch32_SHA256SU0_T1_A",
    "aarch32_SHA1M_T1_A",
}


def is_vector(encoding):
    if encoding in VECTOR_INSTS:
        return True
    return False


def is_coproc(encoding):
    if encoding in COPROC_INSTS:
        return True
    return False


def is_special(encoding):
    if encoding in SPECIAL_INSTS:
        return True
    return False


def is_sha(encoding):
    if encoding in SHA_INSTS:
        return True
    return False


def is_atomatic64(encoding):
    if encoding.startswith("aarch64_memory_atomicops"):
        return True
    return False


def is_exclusive64(encoding):
    if encoding.startswith("aarch64_memory_exclusive"):
        return True
    return False


def is_vector64(encoding):
    if encoding.startswith("aarch64_vector"):
        return True
    return False


def is_system64(encoding):
    if encoding.startswith("aarch64_system"):
        return True
    return False


def is_float64(encoding):
    if encoding.startswith("aarch64_float"):
        return True
    return False


def is_unpriv64(encoding):
    if "unpriv" in encoding:
        return True
    return False


def is_special64(encoding):
    encodings = {
        "aarch64_memory_pair_general_no_alloc_stnp_gen",
        "aarch64_memory_pair_general_no_alloc_ldnp_gen",
        "aarch64_integer_arithmetic_mul_widening_64_128hi_smulh",
        "aarch64_integer_arithmetic_mul_widening_64_128hi_umulh",
    }
    if encoding in encodings:
        return True
    return False


def is_prefetch64(encoding, code):
    encodings = {
        "aarch64_memory_literal_general_prfm_lit",
        "aarch64_memory_single_general_register_prfm_reg",
        "aarch64_memory_single_general_immediate_signed_offset_normal_prfum",
    }
    if encoding in encodings:
        return True
    if encoding == "aarch64_memory_literal_general_ldr_lit_gen":
        opc = code[0:2]
        if opc == "11":
            return True
    return False


def filter(encoding, code):
    if is_vector(encoding):
        return True
    if is_coproc(encoding):
        return True
    if is_special(encoding):
        return True
    if is_sha(encoding):
        return True
    if is_atomatic64(encoding):
        return True
    if is_exclusive64(encoding):
        return True
    if is_vector64(encoding):
        return True
    if is_system64(encoding):
        return True
    if is_float64(encoding):
        return True
    if is_unpriv64(encoding):
        return True
    if is_special64(encoding):
        return True
    if is_prefetch64(encoding, code):
        return True
    return False
