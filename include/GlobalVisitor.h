#ifndef GLOBALVISITOR_H
#define GLOBALVISITOR_H

#include "llvm_basics.h"
#include <llvm/IR/InstVisitor.h>
#include <type_traits>
#include <vector>
#include <memory>
#include "VisitorCallback.h"
#include "ContextBase.h"
#include "Utils.h"

struct Rules {
    static bool checkBlacklist(Function *func) {
        if (Globals::SkipFuncs.count(func->getName()) != 0)
            // func->getName().equals("CRYPTO_lock")
            // || func->getName().equals("ERR_put_error")
            // || func->getName().equals("RAND_bytes")
            // || func->getName().equals("RAND_pseudo_bytes")
            // || func->getName().equals("RAND_add")
            // || func->getName().equals("ASN1_item_ex_i2d")
            // || func->getName().equals("ASN1_item_ex_d2i")
            // || func->getName().equals("ERR_load_ENGINE_strings")
            // || func->getName().equals("ERR_load_CRYPTO_strings")
            // || func->getName().equals("ERR_load_OBJ_strings")
            // || func->getName().equals("ERR_load_BN_strings")
            // || func->getName().equals("ERR_load_EC_strings")
            // || func->getName().equals("ERR_load_RSA_strings")
            // || func->getName().equals("ERR_load_DSA_strings")
            // || func->getName().equals("ERR_load_ECDSA_strings")
            // || func->getName().equals("ERR_load_DH_strings")
            // || func->getName().equals("ERR_load_ECDH_strings")
            // || func->getName().equals("ERR_load_DSO_strings")
            // || func->getName().equals("ERR_load_ENGINE_strings")
            // || func->getName().equals("ERR_load_BUF_strings")
            // || func->getName().equals("ERR_load_BIO_strings")
            // || func->getName().equals("ERR_load_RAND_strings")
            // || func->getName().equals("ERR_get_implementation")
            // || func->getName().equals("ERR_set_implementation")
            // || func->getName().equals("ERR_load_ERR_strings")
            // || func->getName().equals("ERR_load_strings")
            // || func->getName().equals("ERR_unload_strings")
            // || func->getName().equals("ERR_free_strings")
            // || func->getName().equals("ERR_put_error")
            // || func->getName().equals("ERR_get_state")
            // || func->getName().equals("ERR_clear_error")
            // || func->getName().equals("ERR_get_error")
            // || func->getName().equals("ERR_get_error_line")
            // || func->getName().equals("ERR_get_error_line_data")
            // || func->getName().equals("ERR_peek_error")
            // || func->getName().equals("ERR_peek_error_line")
            // || func->getName().equals("ERR_peek_error_line_data")
            // || func->getName().equals("ERR_peek_last_error")
            // || func->getName().equals("ERR_peek_last_error_line")
            // || func->getName().equals("ERR_peek_last_error_line_data")
            // || func->getName().equals("ERR_error_string_n")
            // || func->getName().equals("ERR_lib_error_string")
            // || func->getName().equals("ERR_func_error_string")
            // || func->getName().equals("ERR_reason_error_string")
            // || func->getName().equals("ERR_error_string")
            // || func->getName().equals("ERR_get_string_table")
            // || func->getName().equals("ERR_get_err_state_table")
            // || func->getName().equals("ERR_release_err_state_table")
            // || func->getName().equals("ERR_remove_thread_state")
            // || func->getName().equals("ERR_remove_state")
            // || func->getName().equals("ERR_STATE_free")
            // || func->getName().equals("ERR_get_next_error_library")
            // || func->getName().equals("ERR_set_error_data")
            // || func->getName().equals("ERR_add_error_data")
            // || func->getName().equals("ERR_add_error_vdata")
            // || func->getName().equals("ERR_set_mark")
            // || func->getName().equals("ERR_pop_to_mark")
            // || func->getName().equals("ERR_load_crypto_strings")
            // || func->getName().equals("ERR_print_errors_cb")
            // || func->getName().equals("ERR_print_errors_fp")
            // || func->getName().equals("ERR_print_errors")
            // || func->getName().equals("ERR_load_EVP_strings")
            // || func->getName().equals("ERR_load_ASN1_strings")
            // || func->getName().equals("ERR_load_PEM_strings")
            // || func->getName().equals("ERR_load_X509_strings")
            // || func->getName().equals("ERR_load_X509V3_strings")
            // || func->getName().equals("ERR_load_CONF_strings")
            // || func->getName().equals("ERR_load_PKCS7_strings")
            // || func->getName().equals("ERR_load_PKCS12_strings")
            // || func->getName().equals("ERR_load_COMP_strings")
            // || func->getName().equals("ERR_load_OCSP_strings")
            // || func->getName().equals("ERR_load_UI_strings")
            // || func->getName().equals("ERR_load_CMS_strings")
            // || func->getName().equals("ERR_load_TS_strings")
            // || func->getName().equals("ENGINE_finish") 
            // || func->getName().equals("lh_new") 
            // || func->getName().equals("lh_strhash")  
            // || func->getName().equals("lh_free")  
            // || func->getName().equals("lh_insert")  
            // || func->getName().equals("lh_delete")  
            // || func->getName().equals("lh_retrieve")  
            // || func->getName().equals("lh_doall")  
            // || func->getName().equals("lh_doall_arg")  
            // || func->getName().equals("lh_num_items")  
            // || func->getName().equals("lh_stats")  
            // || func->getName().equals("lh_stats_bio")  
            // || func->getName().equals("lh_node_stats")  
            // || func->getName().equals("lh_node_stats_bio")  
            // || func->getName().equals("lh_node_usage_stats")  
            // || func->getName().equals("lh_node_usage_stats_bio")
            // || func->getName().equals("EC_EX_DATA_clear_free_all_data")
            // || func->getName().equals("EC_EX_DATA_clear_free_data")
            // || func->getName().equals("EC_EX_DATA_free_all_data")
            // || func->getName().equals("EC_EX_DATA_free_data")
            // || func->getName().equals("EC_EX_DATA_get_data")
            // || func->getName().equals("EC_EX_DATA_set_data")
            // || func->getName().equals("EC_GF2m_simple_method")
            // || func->getName().equals("EC_GFp_mont_method")
            // || func->getName().equals("EC_GFp_nist_method")
            // || func->getName().equals("EC_GFp_simple_method")
            // || func->getName().equals("EC_GROUP_check")
            // || func->getName().equals("EC_GROUP_check_discriminant")
            // || func->getName().equals("EC_GROUP_clear_free")
            // || func->getName().equals("EC_GROUP_cmp")
            // || func->getName().equals("EC_GROUP_copy")
            // || func->getName().equals("EC_GROUP_dup")
            // || func->getName().equals("EC_GROUP_free")
            // || func->getName().equals("EC_GROUP_get0_generator")
            // || func->getName().equals("EC_GROUP_get0_seed")
            // || func->getName().equals("EC_GROUP_get_asn1_flag")
            // || func->getName().equals("EC_GROUP_get_basis_type")
            // || func->getName().equals("EC_GROUP_get_cofactor")
            // || func->getName().equals("EC_GROUP_get_curve_GF2m")
            // || func->getName().equals("EC_GROUP_get_curve_GFp")
            // || func->getName().equals("EC_GROUP_get_curve_name")
            // || func->getName().equals("EC_GROUP_get_degree")
            // || func->getName().equals("EC_GROUP_get_mont_data")
            // || func->getName().equals("EC_GROUP_get_order")
            // || func->getName().equals("EC_GROUP_get_pentanomial_basis")
            // || func->getName().equals("EC_GROUP_get_point_conversion_form")
            // || func->getName().equals("EC_GROUP_get_seed_len")
            // || func->getName().equals("EC_GROUP_get_trinomial_basis")
            // || func->getName().equals("EC_GROUP_have_precompute_mult")
            // || func->getName().equals("EC_GROUP_method_of")
            // || func->getName().equals("EC_GROUP_new")
            // || func->getName().equals("EC_GROUP_new_by_curve_name")
            // || func->getName().equals("EC_GROUP_new_curve_GF2m")
            // || func->getName().equals("EC_GROUP_new_curve_GFp")
            // || func->getName().equals("EC_GROUP_precompute_mult")
            // || func->getName().equals("EC_GROUP_set_asn1_flag")
            // || func->getName().equals("EC_GROUP_set_curve_GF2m")
            // || func->getName().equals("EC_GROUP_set_curve_GFp")
            // || func->getName().equals("EC_GROUP_set_curve_name")
            // || func->getName().equals("EC_GROUP_set_generator")
            // || func->getName().equals("EC_GROUP_set_point_conversion_form")
            // || func->getName().equals("EC_GROUP_set_seed")
            // || func->getName().equals("EC_KEY_check_key")
            // || func->getName().equals("EC_KEY_clear_flags")
            // || func->getName().equals("EC_KEY_copy")
            // || func->getName().equals("EC_KEY_dup")
            // || func->getName().equals("EC_KEY_free")
            // || func->getName().equals("EC_KEY_generate_key")
            // || func->getName().equals("EC_KEY_get0_group")
            // || func->getName().equals("EC_KEY_get0_private_key")
            // || func->getName().equals("EC_KEY_get0_public_key")
            // || func->getName().equals("EC_KEY_get_conv_form")
            // || func->getName().equals("EC_KEY_get_enc_flags")
            // || func->getName().equals("EC_KEY_get_flags")
            // || func->getName().equals("EC_KEY_get_key_method_data")
            // || func->getName().equals("EC_KEY_insert_key_method_data")
            // || func->getName().equals("EC_KEY_new")
            // || func->getName().equals("EC_KEY_new_by_curve_name")
            // || func->getName().equals("EC_KEY_precompute_mult")
            // || func->getName().equals("EC_KEY_print")
            // || func->getName().equals("EC_KEY_print_fp")
            // || func->getName().equals("EC_KEY_set_asn1_flag")
            // || func->getName().equals("EC_KEY_set_conv_form")
            // || func->getName().equals("EC_KEY_set_enc_flags")
            // || func->getName().equals("EC_KEY_set_flags")
            // || func->getName().equals("EC_KEY_set_group")
            // || func->getName().equals("EC_KEY_set_private_key")
            // || func->getName().equals("EC_KEY_set_public_key")
            // || func->getName().equals("EC_KEY_set_public_key_affine_coordinates")
            // || func->getName().equals("EC_KEY_up_ref")
            // || func->getName().equals("EC_METHOD_get_field_type")
            // || func->getName().equals("EC_POINT_add")
            // || func->getName().equals("EC_POINT_bn2point")
            // || func->getName().equals("EC_POINT_clear_free")
            // || func->getName().equals("EC_POINT_cmp")
            // || func->getName().equals("EC_POINT_copy")
            // || func->getName().equals("EC_POINT_dbl")
            // || func->getName().equals("EC_POINT_dup")
            // || func->getName().equals("EC_POINT_free")
            // || func->getName().equals("EC_POINT_get_Jprojective_coordinates_GFp")
            // || func->getName().equals("EC_POINT_get_affine_coordinates_GF2m")
            // || func->getName().equals("EC_POINT_get_affine_coordinates_GFp")
            // || func->getName().equals("EC_POINT_hex2point")
            // || func->getName().equals("EC_POINT_invert")
            // || func->getName().equals("EC_POINT_is_at_infinity")
            // || func->getName().equals("EC_POINT_is_on_curve")
            // || func->getName().equals("EC_POINT_make_affine")
            // || func->getName().equals("EC_POINT_method_of")
            // || func->getName().equals("EC_POINT_mul")
            // || func->getName().equals("EC_POINT_new")
            // || func->getName().equals("EC_POINT_oct2point")
            // || func->getName().equals("EC_POINT_point2bn")
            // || func->getName().equals("EC_POINT_point2hex")
            // || func->getName().equals("EC_POINT_point2oct")
            // || func->getName().equals("EC_POINT_set_Jprojective_coordinates_GFp")
            // || func->getName().equals("EC_POINT_set_affine_coordinates_GF2m")
            // || func->getName().equals("EC_POINT_set_affine_coordinates_GFp")
            // || func->getName().equals("EC_POINT_set_compressed_coordinates_GF2m")
            // || func->getName().equals("EC_POINT_set_compressed_coordinates_GFp")
            // || func->getName().equals("EC_POINT_set_to_infinity")
            // || func->getName().equals("EC_POINTs_make_affine")
            // || func->getName().equals("EC_POINTs_mul")
            // || func->getName().equals("EC_PRIVATEKEY_free")
            // || func->getName().equals("EC_PRIVATEKEY_new")
            // || func->getName().equals("EC_curve_nid2nist")
            // || func->getName().equals("EC_curve_nist2nid")
            // || func->getName().equals("EC_get_builtin_curves")
            // || func->getName().equals("ec_GF2m_have_precompute_mult")
            // || func->getName().equals("ec_GF2m_montgomery_point_multiply")
            // || func->getName().equals("ec_GF2m_precompute_mult")
            // || func->getName().equals("ec_GF2m_simple_add")
            // || func->getName().equals("ec_GF2m_simple_cmp")
            // || func->getName().equals("ec_GF2m_simple_dbl")
            // || func->getName().equals("ec_GF2m_simple_field_div")
            // || func->getName().equals("ec_GF2m_simple_field_mul")
            // || func->getName().equals("ec_GF2m_simple_field_sqr")
            // || func->getName().equals("ec_GF2m_simple_group_check_discriminant")
            // || func->getName().equals("ec_GF2m_simple_group_clear_finish")
            // || func->getName().equals("ec_GF2m_simple_group_copy")
            // || func->getName().equals("ec_GF2m_simple_group_finish")
            // || func->getName().equals("ec_GF2m_simple_group_get_curve")
            // || func->getName().equals("ec_GF2m_simple_group_get_degree")
            // || func->getName().equals("ec_GF2m_simple_group_init")
            // || func->getName().equals("ec_GF2m_simple_group_set_curve")
            // || func->getName().equals("ec_GF2m_simple_invert")
            // || func->getName().equals("ec_GF2m_simple_is_at_infinity")
            // || func->getName().equals("ec_GF2m_simple_is_on_curve")
            // || func->getName().equals("ec_GF2m_simple_make_affine")
            // || func->getName().equals("ec_GF2m_simple_mul")
            // || func->getName().equals("ec_GF2m_simple_oct2point")
            // || func->getName().equals("ec_GF2m_simple_point2oct")
            // || func->getName().equals("ec_GF2m_simple_point_clear_finish")
            // || func->getName().equals("ec_GF2m_simple_point_copy")
            // || func->getName().equals("ec_GF2m_simple_point_finish")
            // || func->getName().equals("ec_GF2m_simple_point_get_affine_coordinates")
            // || func->getName().equals("ec_GF2m_simple_point_init")
            // || func->getName().equals("ec_GF2m_simple_point_set_affine_coordinates")
            // || func->getName().equals("ec_GF2m_simple_point_set_to_infinity")
            // || func->getName().equals("ec_GF2m_simple_points_make_affine")
            // || func->getName().equals("ec_GF2m_simple_set_compressed_coordinates")
            // || func->getName().equals("ec_GFp_mont_field_decode")
            // || func->getName().equals("ec_GFp_mont_field_encode")
            // || func->getName().equals("ec_GFp_mont_field_mul")
            // || func->getName().equals("ec_GFp_mont_field_set_to_one")
            // || func->getName().equals("ec_GFp_mont_field_sqr")
            // || func->getName().equals("ec_GFp_mont_group_clear_finish")
            // || func->getName().equals("ec_GFp_mont_group_copy")
            // || func->getName().equals("ec_GFp_mont_group_finish")
            // || func->getName().equals("ec_GFp_mont_group_init")
            // || func->getName().equals("ec_GFp_mont_group_set_curve")
            // || func->getName().equals("ec_GFp_nist_field_mul")
            // || func->getName().equals("ec_GFp_nist_field_sqr")
            // || func->getName().equals("ec_GFp_nist_group_copy")
            // || func->getName().equals("ec_GFp_nist_group_set_curve")
            // || func->getName().equals("ec_GFp_simple_add")
            // || func->getName().equals("ec_GFp_simple_cmp")
            // || func->getName().equals("ec_GFp_simple_dbl")
            // || func->getName().equals("ec_GFp_simple_field_mul")
            // || func->getName().equals("ec_GFp_simple_field_sqr")
            // || func->getName().equals("ec_GFp_simple_get_Jprojective_coordinates_GFp")
            // || func->getName().equals("ec_GFp_simple_group_check_discriminant")
            // || func->getName().equals("ec_GFp_simple_group_clear_finish")
            // || func->getName().equals("ec_GFp_simple_group_copy")
            // || func->getName().equals("ec_GFp_simple_group_finish")
            // || func->getName().equals("ec_GFp_simple_group_get_curve")
            // || func->getName().equals("ec_GFp_simple_group_get_degree")
            // || func->getName().equals("ec_GFp_simple_group_init")
            // || func->getName().equals("ec_GFp_simple_group_set_curve")
            // || func->getName().equals("ec_GFp_simple_invert")
            // || func->getName().equals("ec_GFp_simple_is_at_infinity")
            // || func->getName().equals("ec_GFp_simple_is_on_curve")
            // || func->getName().equals("ec_GFp_simple_make_affine")
            // || func->getName().equals("ec_GFp_simple_oct2point")
            // || func->getName().equals("ec_GFp_simple_point2oct")
            // || func->getName().equals("ec_GFp_simple_point_clear_finish")
            // || func->getName().equals("ec_GFp_simple_point_copy")
            // || func->getName().equals("ec_GFp_simple_point_finish")
            // || func->getName().equals("ec_GFp_simple_point_get_affine_coordinates")
            // || func->getName().equals("ec_GFp_simple_point_init")
            // || func->getName().equals("ec_GFp_simple_point_set_affine_coordinates")
            // || func->getName().equals("ec_GFp_simple_point_set_to_infinity")
            // || func->getName().equals("ec_GFp_simple_points_make_affine")
            // || func->getName().equals("ec_GFp_simple_set_Jprojective_coordinates_GFp")
            // || func->getName().equals("ec_GFp_simple_set_compressed_coordinates")
            // || func->getName().equals("ec_asn1_group2pkparameters")
            // || func->getName().equals("ec_asn1_pkparameters2group")
            // || func->getName().equals("ec_bits")
            // || func->getName().equals("ec_cmp_parameters")
            // || func->getName().equals("ec_copy_parameters")
            // || func->getName().equals("ec_missing_parameters")
            // || func->getName().equals("ec_pkey_ctrl")
            // || func->getName().equals("ec_pre_comp_clear_free")
            // || func->getName().equals("ec_pre_comp_dup")
            // || func->getName().equals("ec_pre_comp_free")
            // || func->getName().equals("ec_precompute_mont_data")
            // || func->getName().equals("ec_wNAF_have_precompute_mult")
            // || func->getName().equals("ec_wNAF_mul")
            // || func->getName().equals("ec_wNAF_precompute_mult")


            // || func->getName().equals("_ASN1_ENUMERATED_set")
            // || func->getName().equals("_i2d_ASN1_SET")
            // || func->getName().equals("_i2a_ASN1_OBJECT")
            // || func->getName().equals("_ASN1_template_new")
            // || func->getName().equals("_d2i_ASN1_SET")
            // || func->getName().equals("_ASN1_item_pack")
            // || func->getName().equals("_ASN1_item_unpack")
            // || func->getName().equals("_ASN1_OBJECT_new")
            // || func->getName().equals("_ASN1_d2i_bio")
            // || func->getName().equals("_asn1_enc_save")
            // || func->getName().equals("_ASN1_ENUMERATED_to_BN")
            // || func->getName().equals("_s2i_ASN1_INTEGER")
            // || func->getName().equals("_ASN1_primitive_free")
            // || func->getName().equals("_PEM_ASN1_write_bio")
            // || func->getName().equals("_ASN1_GENERALIZEDTIME_adj")
            // || func->getName().equals("_asn1_ex_i2c")
            // || func->getName().equals("_EVP_PKEY_asn1_find_str")
            // || func->getName().equals("_asn1_template_print_ctx")
            // || func->getName().equals("_ASN1_UTCTIME_print")
            // || func->getName().equals("_a2d_ASN1_OBJECT")
            // || func->getName().equals("_i2s_ASN1_ENUMERATED")
            // || func->getName().equals("_EVP_PKEY_asn1_add0")
            // || func->getName().equals("_ASN1_UTCTIME_adj")
            // || func->getName().equals("_PEM_ASN1_write")
            // || func->getName().equals("_ASN1_TYPE_cmp")
            // || func->getName().equals("_s2i_ASN1_OCTET_STRING")
            // || func->getName().equals("_SMIME_write_ASN1")
            // || func->getName().equals("_ENGINE_pkey_asn1_find_str")
            // || func->getName().equals("_ASN1_item_dup")
            // || func->getName().equals("_d2i_ASN1_OBJECT")
            // || func->getName().equals("_ASN1_item_verify")
            // || func->getName().equals("_ENGINE_get_pkey_asn1_meth")
            // || func->getName().equals("_i2s_ASN1_INTEGER")
            // || func->getName().equals("_ASN1_INTEGER_to_BN")
            // || func->getName().equals("_ASN1_GENERALIZEDTIME_print")
            // || func->getName().equals("_ASN1_item_d2i_fp")
            // || func->getName().equals("_ASN1_TIME_diff")
            // || func->getName().equals("_ASN1_TYPE_set_octetstring")
            // || func->getName().equals("_ASN1_INTEGER_set")
            // || func->getName().equals("_d2i_ASN1_UINTEGER")
            // || func->getName().equals("_TS_ASN1_INTEGER_print_bio")
            // || func->getName().equals("_SMIME_read_ASN1")
            // || func->getName().equals("_ASN1_TIME_adj")
            // || func->getName().equals("_ASN1_TYPE_set_int_octetstring")
            // || func->getName().equals("_ASN1_dup")
            // || func->getName().equals("_ASN1_STRING_set_by_NID")
            // || func->getName().equals("_ASN1_item_ex_i2d")
            // || func->getName().equals("_ASN1_STRING_print")
            // || func->getName().equals("_ASN1_mbstring_ncopy")
            // || func->getName().equals("_c2i_ASN1_BIT_STRING")
            // || func->getName().equals("_asn1_utctime_to_tm")
            // || func->getName().equals("_ASN1_get_object")
            // || func->getName().equals("_EVP_PKEY_asn1_find")
            // || func->getName().equals("_i2c_ASN1_BIT_STRING")
            // || func->getName().equals("_ASN1_item_i2d_bio")
            // || func->getName().equals("_BN_to_ASN1_INTEGER")
            // || func->getName().equals("_ASN1_i2d_bio")
            // || func->getName().equals("_ASN1_generate_v3")
            // || func->getName().equals("_EVP_PKEY_asn1_free")
            // || func->getName().equals("_PEM_ASN1_read")
            // || func->getName().equals("_i2d_ASN1_bio_stream")
            // || func->getName().equals("_asn1_do_adb")
            // || func->getName().equals("_ASN1_d2i_fp")
            // || func->getName().equals("_ASN1_bn_print")
            // || func->getName().equals("_ASN1_item_sign_ctx")
            // || func->getName().equals("_ASN1_OBJECT_free")
            // || func->getName().equals("_asn1_generalizedtime_to_tm")
            // || func->getName().equals("_ASN1_item_ex_d2i")
            // || func->getName().equals("_RSA_sign_ASN1_OCTET_STRING")
            // || func->getName().equals("_ASN1_TYPE_get_int_octetstring")
            // || func->getName().equals("_ASN1_TIME_to_generalizedtime")
            // || func->getName().equals("_EVP_PKEY_asn1_free_10881338769681343115")
            // || func->getName().equals("_d2i_ASN1_BOOLEAN")
            // || func->getName().equals("_ASN1_TYPE_set1")
            // || func->getName().equals("_asn1_item_combine_free")
            // || func->getName().equals("_cms_env_asn1_ctrl")
            // || func->getName().equals("_ASN1_item_d2i_bio")
            // || func->getName().equals("_asn1_ex_c2i")
            // || func->getName().equals("_ASN1_template_free")
            // || func->getName().equals("_ASN1_primitive_new")
            // || func->getName().equals("_ASN1_STRING_dup")
            // || func->getName().equals("_ERR_load_ASN1_strings")
            // || func->getName().equals("_ASN1_i2d_fp")
            // || func->getName().equals("_c2i_ASN1_OBJECT")
            // || func->getName().equals("_i2c_ASN1_INTEGER")
            // || func->getName().equals("_ASN1_BIT_STRING_set_bit")
            // || func->getName().equals("_PEM_ASN1_read_bio")
            // || func->getName().equals("_EVP_CIPHER_param_to_asn1")
            // || func->getName().equals("_ASN1_TYPE_get_octetstring")
            // || func->getName().equals("_ASN1_STRING_set")
            // || func->getName().equals("_ASN1_item_i2d_fp")
            // || func->getName().equals("_c2i_ASN1_INTEGER")
            // || func->getName().equals("_ASN1_STRING_type_new")
            // || func->getName().equals("_ASN1_STRING_clear_free")
            // || func->getName().equals("_i2a_ASN1_STRING")
            // || func->getName().equals("_i2a_ASN1_INTEGER")
            // || func->getName().equals("engine_pkey_asn1_meths_free")
            // || func->getName().equals("EVP_PKEY_asn1_free")
            // || func->getName().equals("ASN1_item_free")
            // || func->getName().equals("asn1_item_combine_free")
            // || func->getName().equals("ASN1_template_free")
            // || func->getName().equals("ASN1_primitive_free")
            // || func->getName().equals("asn1_get_choice_selector")
            // || func->getName().equals("asn1_get_field_ptr")
            // || func->getName().equals("asn1_do_lock")
            // || func->getName().equals("asn1_enc_free")
            // || func->getName().equals("asn1_do_adb")
            // || func->getName().equals("ASN1_INTEGER_get")
            // || func->getName().equals("ASN1_OBJECT_free")
            // || func->getName().equals("ASN1_STRING_free")
            // || func->getName().equals("ASN1_TYPE_get")
            // || func->getName().equals("ASN1_item_i2d")
            // || func->getName().equals("asn1_item_flags_i2d")
            // || func->getName().equals("ASN1_item_ex_i2d")
            // || func->getName().equals("asn1_template_ex_i2d")
            // || func->getName().equals("asn1_i2d_ex_primitive")
            // || func->getName().equals("asn1_enc_restore")
            // || func->getName().equals("ASN1_object_size")
            // || func->getName().equals("ASN1_put_object")
            // || func->getName().equals("ASN1_put_eoc")
            // || func->getName().equals("asn1_ex_i2c")
            // || func->getName().equals("i2c_ASN1_BIT_STRING")
            // || func->getName().equals("i2c_ASN1_INTEGER")
            // || func->getName().equals("ASN1_item_d2i")
            // || func->getName().equals("ASN1_item_ex_d2i")
            // || func->getName().equals("asn1_template_ex_d2i")
            // || func->getName().equals("asn1_d2i_ex_primitive")
            // || func->getName().equals("asn1_check_tlen")
            // || func->getName().equals("ASN1_tag2bit")
            // || func->getName().equals("asn1_set_choice_selector")
            // || func->getName().equals("ASN1_item_ex_new")
            // || func->getName().equals("ASN1_item_ex_free")
            // || func->getName().equals("asn1_enc_save")
            // || func->getName().equals("asn1_item_ex_combine_new")
            // || func->getName().equals("ASN1_template_new")
            // || func->getName().equals("ASN1_primitive_new")
            // || func->getName().equals("asn1_enc_init")
            // || func->getName().equals("ASN1_STRING_type_new")
            // || func->getName().equals("asn1_template_clear")
            // || func->getName().equals("ASN1_get_object")
            // || func->getName().equals("asn1_collect")
            // || func->getName().equals("asn1_ex_c2i")
            // || func->getName().equals("ASN1_TYPE_new")
            // || func->getName().equals("ASN1_TYPE_set")
            // || func->getName().equals("c2i_ASN1_OBJECT")
            // || func->getName().equals("c2i_ASN1_BIT_STRING")
            // || func->getName().equals("c2i_ASN1_INTEGER")
            // || func->getName().equals("ASN1_STRING_set")
            // || func->getName().equals("ASN1_TYPE_free")
            // || func->getName().equals("ASN1_OBJECT_new")
            // || func->getName().equals("ASN1_item_new")
            // || func->getName().equals("asn1_template_noexp_d2i")
            // || func->getName().equals("BN_to_ASN1_INTEGER")
            // || func->getName().equals("i2d_ASN1_INTEGER")
            // || func->getName().equals("ASN1_INTEGER_free")
            // || func->getName().equals("ASN1_STRING_set0")
            // || func->getName().equals("EVP_CIPHER_param_to_asn1")
            // || func->getName().equals("ASN1_STRING_length")
            // || func->getName().equals("ASN1_STRING_data")
            // || func->getName().equals("ASN1_STRING_new")
            // || func->getName().equals("EVP_CIPHER_set_asn1_iv")
            // || func->getName().equals("ASN1_TYPE_set_octetstring")
            // || func->getName().equals("EVP_CIPHER_asn1_to_param")
            // || func->getName().equals("EVP_CIPHER_get_asn1_iv")
            // || func->getName().equals("ASN1_TYPE_get_octetstring")
            // || func->getName().equals("d2i_ASN1_INTEGER")
            // || func->getName().equals("ASN1_INTEGER_to_BN")
            // || func->getName().equals("EVP_PKEY_asn1_find_str")
            // || func->getName().equals("EVP_PKEY_asn1_find")
            // || func->getName().equals("ENGINE_get_pkey_asn1_meth_engine")
            // || func->getName().equals("ENGINE_get_pkey_asn1_meth")
            // || func->getName().equals("ENGINE_get_pkey_asn1_meths")
            // || func->getName().equals("ENGINE_pkey_asn1_find_str")
            // || func->getName().equals("EVP_PKEY_asn1_get_count")
            // || func->getName().equals("EVP_PKEY_asn1_get0")
            // || func->getName().equals("ASN1_bn_print")
            // || func->getName().equals("ASN1_BIT_STRING_free")
            // || func->getName().equals("ASN1_STRING_clear_free")
            // || func->getName().equals("ASN1_INTEGER_set")
            // || func->getName().equals("ASN1_OCTET_STRING_new")
            // || func->getName().equals("ASN1_OCTET_STRING_set")
            // || func->getName().equals("ASN1_OCTET_STRING_free")
            // || func->getName().equals("ec_asn1_group2pkparameters")
            // || func->getName().equals("EC_GROUP_get_asn1_flag")
            // || func->getName().equals("ASN1_BIT_STRING_new")
            // || func->getName().equals("ASN1_BIT_STRING_set")
            // || func->getName().equals("ASN1_INTEGER_new")
            // || func->getName().equals("ASN1_NULL_new")
            // || func->getName().equals("ec_asn1_pkparameters2group")
            // || func->getName().equals("EC_GROUP_set_asn1_flag")
            // || func->getName().equals("d2i_ASN1_SEQUENCE_ANY")
            // || func->getName().equals("d2i_ASN1_UINTEGER")
            // || func->getName().equals("ASN1_STRING_dup")
            // || func->getName().equals("ASN1_STRING_copy")
            // || func->getName().equals("ASN1_item_pack")
            // || func->getName().equals("ASN1_OCTET_STRING_dup")
            // || func->getName().equals("RSA_sign_ASN1_OCTET_STRING")
            // || func->getName().equals("i2d_ASN1_OCTET_STRING")
            // || func->getName().equals("i2a_ASN1_OBJECT")
            // || func->getName().equals("i2a_ASN1_INTEGER")
            // || func->getName().equals("i2t_ASN1_OBJECT")
            // || func->getName().equals("RSA_verify_ASN1_OCTET_STRING")
            // || func->getName().equals("d2i_ASN1_OCTET_STRING")
            // || func->getName().equals("rc2_set_asn1_type_and_iv")
            // || func->getName().equals("rc2_get_asn1_type_and_iv")
            // || func->getName().equals("ASN1_TYPE_get_int_octetstring")
            // || func->getName().equals("asn1_GetSequence")
            // || func->getName().equals("ASN1_const_check_infinite_end")
            // || func->getName().equals("ASN1_TYPE_set_int_octetstring")
            // || func->getName().equals("i2d_ASN1_bytes")
            // || func->getName().equals("i2d_ASN1_BIT_STRING")
            // || func->getName().equals("ASN1_tag2str")
            // || func->getName().equals("i2d_ASN1_TYPE")
            // || func->getName().equals("ASN1_STRING_to_UTF8")
            // || func->getName().equals("ASN1_mbstring_copy")
            // || func->getName().equals("ASN1_mbstring_ncopy")
            // || func->getName().equals("ASN1_STRING_cmp")
            // || func->getName().equals("ASN1_ENUMERATED_get")
            // || func->getName().equals("ASN1_ENUMERATED_free")
            // || func->getName().equals("ASN1_GENERALIZEDTIME_new")
            // || func->getName().equals("ASN1_GENERALIZEDTIME_adj")
            // || func->getName().equals("ASN1_GENERALIZEDTIME_set_string")
            // || func->getName().equals("ASN1_GENERALIZEDTIME_print")
            // || func->getName().equals("ASN1_GENERALIZEDTIME_free")
            // || func->getName().equals("ASN1_GENERALIZEDTIME_check")
            // || func->getName().equals("asn1_generalizedtime_to_tm")
            // || func->getName().equals("ASN1_BIT_STRING_get_bit")
            // || func->getName().equals("ASN1_generate_v3")
            // || func->getName().equals("asn1_cb")
            // || func->getName().equals("d2i_ASN1_TYPE")
            // || func->getName().equals("s2i_ASN1_INTEGER")
            // || func->getName().equals("ASN1_TIME_check")
            // || func->getName().equals("ASN1_BIT_STRING_set_bit")
            // || func->getName().equals("ASN1_UTCTIME_check")
            // || func->getName().equals("asn1_utctime_to_tm")
            // || func->getName().equals("i2d_ASN1_SET_ANY")
            // || func->getName().equals("i2d_ASN1_SEQUENCE_ANY")
            // || func->getName().equals("ASN1_item_dup")
            // || func->getName().equals("ASN1_STRING_set_by_NID")
            // || func->getName().equals("ASN1_PRINTABLE_type")
            // || func->getName().equals("ASN1_STRING_TABLE_get")
            // || func->getName().equals("a2d_ASN1_OBJECT")
            // || func->getName().equals("d2i_ASN1_OBJECT")
            // || func->getName().equals("i2s_ASN1_INTEGER")
            // || func->getName().equals("s2i_asn1_int")
            // || func->getName().equals("ASN1_STRING_print")
            // || func->getName().equals("i2a_ASN1_STRING")
            // || func->getName().equals("i2s_ASN1_ENUMERATED_TABLE")
            // || func->getName().equals("i2s_ASN1_ENUMERATED")
            // || func->getName().equals("ASN1_ENUMERATED_to_BN")
            // || func->getName().equals("i2v_ASN1_BIT_STRING")
            // || func->getName().equals("v2i_ASN1_BIT_STRING")
            // || func->getName().equals("i2s_ASN1_OCTET_STRING")
            // || func->getName().equals("s2i_ASN1_OCTET_STRING")
            // || func->getName().equals("i2s_ASN1_IA5STRING")
            // || func->getName().equals("s2i_ASN1_IA5STRING")
            // || func->getName().equals("ASN1_item_digest")
            // || func->getName().equals("ASN1_item_verify")
            // || func->getName().equals("ASN1_INTEGER_cmp")
            // || func->getName().equals("asn1_bio_write")
            // || func->getName().equals("asn1_bio_read")
            // || func->getName().equals("asn1_bio_puts")
            // || func->getName().equals("asn1_bio_gets")
            // || func->getName().equals("asn1_bio_ctrl")
            // || func->getName().equals("asn1_bio_new")
            // || func->getName().equals("asn1_bio_free")
            // || func->getName().equals("asn1_bio_callback_ctrl")
            // || func->getName().equals("ASN1_UTCTIME_adj")
            // || func->getName().equals("ASN1_TIME_adj")
            // || func->getName().equals("ASN1_item_d2i_bio")
            // || func->getName().equals("asn1_d2i_read_bio")
            // || func->getName().equals("ASN1_OCTET_STRING_cmp")
            // || func->getName().equals("PEM_ASN1_read_bio")
            // || func->getName().equals("ASN1_TIME_free")
            // || func->getName().equals("ASN1_TYPE_set1")
            // || func->getName().equals("cms_env_asn1_ctrl")
            // || func->getName().equals("ASN1_OBJECT_create")
            // || func->getName().equals("EC_KEY_set_asn1_flag")
            // || func->getName().equals("ENGINE_set_default_pkey_asn1_meths")
            // || func->getName().equals("engine_unregister_all_pkey_asn1_meths")
            // || func->getName().equals("ENGINE_register_pkey_asn1_meths")
            // || func->getName().equals("ENGINE_unregister_pkey_asn1_meths")
            // || func->getName().equals("ENGINE_register_all_pkey_asn1_meths")
            // || func->getName().equals("ENGINE_set_pkey_asn1_meths")
            // || func->getName().equals("ENGINE_get_pkey_asn1_meth_str")
            // || func->getName().equals("ERR_load_ASN1_strings")
            // || func->getName().equals("ASN1_add_oid_module")
            // || func->getName().equals("i2d_ASN1_OBJECT")
            // || func->getName().equals("ASN1_BIT_STRING_check")
            // || func->getName().equals("ASN1_UTCTIME_set_string")
            // || func->getName().equals("ASN1_UTCTIME_set")
            // || func->getName().equals("ASN1_UTCTIME_cmp_time_t")
            // || func->getName().equals("ASN1_GENERALIZEDTIME_set")
            // || func->getName().equals("d2i_ASN1_TIME")
            // || func->getName().equals("i2d_ASN1_TIME")
            // || func->getName().equals("ASN1_TIME_new")
            // || func->getName().equals("ASN1_TIME_set")
            // || func->getName().equals("ASN1_TIME_to_generalizedtime")
            // || func->getName().equals("ASN1_TIME_set_string")
            // || func->getName().equals("ASN1_TIME_diff")
            // || func->getName().equals("ASN1_INTEGER_dup")
            // || func->getName().equals("ASN1_UNIVERSALSTRING_to_string")
            // || func->getName().equals("ASN1_TYPE_cmp")
            // || func->getName().equals("i2d_ASN1_SET")
            // || func->getName().equals("d2i_ASN1_SET")
            // || func->getName().equals("asn1_add_error")
            // || func->getName().equals("ASN1_dup")
            // || func->getName().equals("ASN1_d2i_fp")
            // || func->getName().equals("ASN1_d2i_bio")
            // || func->getName().equals("ASN1_item_d2i_fp")
            // || func->getName().equals("ASN1_i2d_fp")
            // || func->getName().equals("ASN1_i2d_bio")
            // || func->getName().equals("ASN1_item_i2d_fp")
            // || func->getName().equals("ASN1_item_i2d_bio")
            // || func->getName().equals("ASN1_ENUMERATED_set")
            // || func->getName().equals("BN_to_ASN1_ENUMERATED")
            // || func->getName().equals("ASN1_sign")
            // || func->getName().equals("ASN1_item_sign")
            // || func->getName().equals("ASN1_item_sign_ctx")
            // || func->getName().equals("ASN1_digest")
            // || func->getName().equals("ASN1_verify")
            // || func->getName().equals("ASN1_STRING_print_ex")
            // || func->getName().equals("ASN1_STRING_print_ex_fp")
            // || func->getName().equals("ASN1_UTF8STRING_free")
            // || func->getName().equals("ASN1_UTF8STRING_new")
            // || func->getName().equals("ASN1_parse_dump")
            // || func->getName().equals("asn1_parse2")
            // || func->getName().equals("d2i_ASN1_BOOLEAN")
            // || func->getName().equals("d2i_ASN1_ENUMERATED")
            // || func->getName().equals("ASN1_TIME_print")
            // || func->getName().equals("ASN1_UTCTIME_print")
            // || func->getName().equals("ASN1_BIT_STRING_name_print")
            // || func->getName().equals("ASN1_BIT_STRING_set_asc")
            // || func->getName().equals("ASN1_BIT_STRING_num_asc")
            // || func->getName().equals("ASN1_item_ndef_i2d")
            // || func->getName().equals("ASN1_template_i2d")
            // || func->getName().equals("ASN1_template_d2i")
            // || func->getName().equals("i2d_ASN1_ENUMERATED")
            // || func->getName().equals("ASN1_ENUMERATED_new")
            // || func->getName().equals("d2i_ASN1_BIT_STRING")
            // || func->getName().equals("d2i_ASN1_NULL")
            // || func->getName().equals("i2d_ASN1_NULL")
            // || func->getName().equals("ASN1_NULL_free")
            // || func->getName().equals("d2i_ASN1_UTF8STRING")
            // || func->getName().equals("i2d_ASN1_UTF8STRING")
            // || func->getName().equals("d2i_ASN1_PRINTABLESTRING")
            // || func->getName().equals("i2d_ASN1_PRINTABLESTRING")
            // || func->getName().equals("ASN1_PRINTABLESTRING_new")
            // || func->getName().equals("ASN1_PRINTABLESTRING_free")
            // || func->getName().equals("d2i_ASN1_T61STRING")
            // || func->getName().equals("i2d_ASN1_T61STRING")
            // || func->getName().equals("ASN1_T61STRING_new")
            // || func->getName().equals("ASN1_T61STRING_free")
            // || func->getName().equals("d2i_ASN1_IA5STRING")
            // || func->getName().equals("i2d_ASN1_IA5STRING")
            // || func->getName().equals("ASN1_IA5STRING_new")
            // || func->getName().equals("ASN1_IA5STRING_free")
            // || func->getName().equals("d2i_ASN1_GENERALSTRING")
            // || func->getName().equals("i2d_ASN1_GENERALSTRING")
            // || func->getName().equals("ASN1_GENERALSTRING_new")
            // || func->getName().equals("ASN1_GENERALSTRING_free")
            // || func->getName().equals("d2i_ASN1_UTCTIME")
            // || func->getName().equals("i2d_ASN1_UTCTIME")
            // || func->getName().equals("ASN1_UTCTIME_new")
            // || func->getName().equals("ASN1_UTCTIME_free")
            // || func->getName().equals("d2i_ASN1_GENERALIZEDTIME")
            // || func->getName().equals("i2d_ASN1_GENERALIZEDTIME")
            // || func->getName().equals("d2i_ASN1_VISIBLESTRING")
            // || func->getName().equals("i2d_ASN1_VISIBLESTRING")
            // || func->getName().equals("ASN1_VISIBLESTRING_new")
            // || func->getName().equals("ASN1_VISIBLESTRING_free")
            // || func->getName().equals("d2i_ASN1_UNIVERSALSTRING")
            // || func->getName().equals("i2d_ASN1_UNIVERSALSTRING")
            // || func->getName().equals("ASN1_UNIVERSALSTRING_new")
            // || func->getName().equals("ASN1_UNIVERSALSTRING_free")
            // || func->getName().equals("d2i_ASN1_BMPSTRING")
            // || func->getName().equals("i2d_ASN1_BMPSTRING")
            // || func->getName().equals("ASN1_BMPSTRING_new")
            // || func->getName().equals("ASN1_BMPSTRING_free")
            // || func->getName().equals("d2i_ASN1_PRINTABLE")
            // || func->getName().equals("i2d_ASN1_PRINTABLE")
            // || func->getName().equals("ASN1_PRINTABLE_new")
            // || func->getName().equals("ASN1_PRINTABLE_free")
            // || func->getName().equals("d2i_ASN1_SET_ANY")
            // || func->getName().equals("ASN1_PCTX_new")
            // || func->getName().equals("ASN1_PCTX_free")
            // || func->getName().equals("ASN1_PCTX_get_flags")
            // || func->getName().equals("ASN1_PCTX_set_flags")
            // || func->getName().equals("ASN1_PCTX_get_nm_flags")
            // || func->getName().equals("ASN1_PCTX_set_nm_flags")
            // || func->getName().equals("ASN1_PCTX_get_cert_flags")
            // || func->getName().equals("ASN1_PCTX_set_cert_flags")
            // || func->getName().equals("ASN1_PCTX_get_oid_flags")
            // || func->getName().equals("ASN1_PCTX_set_oid_flags")
            // || func->getName().equals("ASN1_PCTX_get_str_flags")
            // || func->getName().equals("ASN1_PCTX_set_str_flags")
            // || func->getName().equals("ASN1_item_print")
            // || func->getName().equals("asn1_item_print_ctx")
            // || func->getName().equals("asn1_print_fsname")
            // || func->getName().equals("asn1_template_print_ctx")
            // || func->getName().equals("EVP_PKEY_asn1_add0")
            // || func->getName().equals("EVP_PKEY_asn1_add_alias")
            // || func->getName().equals("EVP_PKEY_asn1_new")
            // || func->getName().equals("EVP_PKEY_asn1_get0_info")
            // || func->getName().equals("EVP_PKEY_get0_asn1")
            // || func->getName().equals("EVP_PKEY_asn1_copy")
            // || func->getName().equals("EVP_PKEY_asn1_set_public")
            // || func->getName().equals("EVP_PKEY_asn1_set_private")
            // || func->getName().equals("EVP_PKEY_asn1_set_param")
            // || func->getName().equals("EVP_PKEY_asn1_set_free")
            // || func->getName().equals("EVP_PKEY_asn1_set_ctrl")
            // || func->getName().equals("EVP_PKEY_asn1_set_item")
            // || func->getName().equals("a2i_ASN1_INTEGER")
            // || func->getName().equals("a2i_ASN1_STRING")
            // || func->getName().equals("i2a_ASN1_ENUMERATED")
            // || func->getName().equals("a2i_ASN1_ENUMERATED")
            // || func->getName().equals("asn1_const_Finish")
            // || func->getName().equals("i2d_ASN1_BOOLEAN")
            // || func->getName().equals("BIO_f_asn1")
            // || func->getName().equals("BIO_asn1_set_prefix")
            // || func->getName().equals("BIO_asn1_get_prefix")
            // || func->getName().equals("BIO_asn1_set_suffix")
            // || func->getName().equals("BIO_asn1_get_suffix")
            // || func->getName().equals("i2d_ASN1_bio_stream")
            // || func->getName().equals("PEM_write_bio_ASN1_stream")
            // || func->getName().equals("B64_write_ASN1")
            // || func->getName().equals("SMIME_write_ASN1")
            // || func->getName().equals("SMIME_read_ASN1")
            // || func->getName().equals("b64_read_asn1")
            // || func->getName().equals("ASN1_generate_nconf")
            // || func->getName().equals("ASN1_parse")
            // || func->getName().equals("ASN1_check_infinite_end")
            // || func->getName().equals("asn1_Finish")
            // || func->getName().equals("ASN1_STRING_length_set")
            // || func->getName().equals("ASN1_STRING_type")
            // || func->getName().equals("d2i_ASN1_type_bytes")
            // || func->getName().equals("d2i_ASN1_bytes")
            // || func->getName().equals("int_d2i_ASN1_bytes")
            // || func->getName().equals("ASN1_STRING_set_default_mask")
            // || func->getName().equals("ASN1_STRING_get_default_mask")
            // || func->getName().equals("ASN1_STRING_set_default_mask_asc")
            // || func->getName().equals("ASN1_STRING_TABLE_add")
            // || func->getName().equals("ASN1_STRING_TABLE_cleanup")
            // || func->getName().equals("ASN1_seq_unpack")
            // || func->getName().equals("ASN1_seq_pack")
            // || func->getName().equals("ASN1_unpack_string")
            // || func->getName().equals("ASN1_pack_string")
            // || func->getName().equals("ASN1_item_unpack")
            // || func->getName().equals("PEM_ASN1_write_bio")
            // || func->getName().equals("PEM_ASN1_read")
            // || func->getName().equals("PEM_ASN1_write")
            // || func->getName().equals("TS_ASN1_INTEGER_print_bio")
            return true;
        else
            return false;
    }
};


template<typename CtxClass>
class GlobalVisitor: public InstVisitor<GlobalVisitor<CtxClass> > {
    static_assert(
            std::is_base_of<ContextBase<CtxClass>, CtxClass>::value,
            "Type CtxClass should be derived from ContextBase");

    public:
    typedef VisitorCallback<CtxClass> CallbackBase;
    Module &mod;
    Function &entry;
    CtxClass *currCtx;

    private:
    typedef InstVisitor<GlobalVisitor<CtxClass> > VisitorBase;
    std::vector<std::unique_ptr<CallbackBase> > allCallbacks;
    std::vector<std::unique_ptr<CtxClass> > contexts;
    VisitorBase *super;


    public:
    GlobalVisitor(Module &mod, Function &entry)
        : mod(mod), entry(entry), currCtx(nullptr) {
            super = static_cast<VisitorBase*>(this);
            contexts.push_back(std::unique_ptr<CtxClass>(
                        new CtxClass(nullptr, &entry) ));
        }


    template <typename T>
        T* addCallback() {
            static_assert(
                    std::is_base_of<CallbackBase, T>::value,
                    "Type T should be derived from VisitorCallback");
            auto ret = new T(currCtx, mod);
            allCallbacks.push_back(
                    std::unique_ptr<CallbackBase>(ret));
            return ret;
        }


    void clearCallbacks() {
        allCallbacks.clear();
    }


    void analyze() {
        currCtx = contexts[0].get();
        if (Globals::IsLib) currCtx->isdirector = true;
        analyze(entry);
    }


    private:
    CtxClass* pushContext(Instruction &inst, Function *func) {
        auto tmp = currCtx->getOrCreateChildCtx(&inst, func);
        if (tmp.second) contexts.push_back(
                std::unique_ptr<CtxClass>( tmp.first ));
        currCtx = tmp.first;
        return currCtx->parent;
    }


    void analyze(Function &func) {
        DEBUG_CTXTIME(dbgs() << "Enter Function: " << func.getName() << "\n");
        currCtx->init();

        int scc_cnt = 0;
        std::vector<std::vector<BasicBlock*> > traversalOrder;
        getSCCTraversalOrder(func, traversalOrder);

        for (auto &currSCC: traversalOrder) {
            if (currSCC.size() > 1) {
                scc_cnt++;
                unsigned num_to_analyze = getNumTimesToAnalyze(currSCC);
                DEBUG_GVISITOR(dbgs() << "Enter SCC. Loop = " << num_to_analyze+1 << "\n");
                this->currCtx->inside_loop = true;

                for(unsigned i = 0; i < num_to_analyze; i++) {
                    this->visitSCC(currSCC);
                }
                this->currCtx->lastloopiter = true;
                this->currCtx->loopidx = scc_cnt;
            } else 
                this->currCtx->lastloopiter = false;
            
            this->currCtx->inside_loop = false;
            this->visitSCC(currSCC);

            if (currSCC.size() > 1) {
                this->currCtx->lastloopiter = false;
                DEBUG_GVISITOR(dbgs() << "Exit SCC.\n");
            }
        }

        auto totalself = currCtx->get_timer();
        DEBUG_CTXTIME(dbgs() << "Exit Function: " << func.getName()
                << " total = " << totalself.first
                << " self = " << totalself.second << "\n");
    }


    CtxClass* popContext() {
        auto child = currCtx;
        currCtx = child->parent;
        currCtx->consume_childctx(child);
        return child;
    }


    void visitSCC(std::vector<BasicBlock*> &currSCC) {
        for (auto currBB: currSCC) {
            super->visit(currBB);
        }
    }


    public:
    /// called by InstVisitor::visit(BasicBlock&)
    void visitBasicBlock(BasicBlock &BB) {
        DEBUG_GVISITOR(dbgs() << "Visit Basic Block: " << BB.getName() << "\n");
    }


    /// called before each Instruction is handled
    void visit(Instruction &I) {
        for (auto &currCallback: allCallbacks)
            if (currCallback->enabled)
                currCallback->visit(I);
        super->visit(I);
    }


    /// called if Instruction is not handled
    void visitInstruction(Instruction &I) {
        errs() << I << "\n";
        // assert(false);
    }


#define DEFINE_VISIT_FUNC(TYPE) \
    void visit##TYPE(TYPE &I) { \
        for (auto &currCallback: allCallbacks) \
        if (currCallback->enabled) \
        currCallback->visit##TYPE(I); \
    }
#include "Instruction.def"
#undef DEFINE_VISIT_FUNC


    void visitCallInst(CallInst &I) {
        Function *currFunc = I.getCalledFunction();
        if(currCtx->inside_loop && !(currFunc && currFunc->isDeclaration())) {
            errs() << "Function inside loop, will be analyzed at last iteration\n";
            return;
        }

        if(currFunc) {
            this->processCalledFunction(I, currFunc);
        }
        else if (I.isInlineAsm()) {
            return;
            // assert(false);
        }
        else {
            Value *calledValue = I.getCalledValue();
            std::vector<Function*> targets;
            currCtx->getFuncPtrTargets(calledValue, targets);
            if (targets.size()) {
                for (auto func: targets) {
                    if (func->arg_size() == I.getNumArgOperands())
                        this->processCalledFunction(I, func);
                    else 
                        DEBUG_CALLINST(dbgs() << "Number of arguments unmatch: " << I << "\n");
                }
            } else {
                DEBUG_CALLINST(dbgs() << "No targets found: " << I << "\n");
                // benign case found in libsodium: _misuse_handler
                // assert(false);
            }
        }
    }

    void processCalledFunction(CallInst &I, Function *currFunc) {
        std::vector<CallbackBase*> disabledcallbacks;
        bool divein = false;
        for (auto &currCallback: allCallbacks) {
            if (currCallback->enabled) {
                if (currCallback->visitCallInst(I, currFunc)) {
                    divein = true;
                } else {
                    disabledcallbacks.push_back(currCallback.get());
                }
            }
        }

        if (Rules::checkBlacklist(currFunc)) {
            DEBUG_CALLINST(dbgs() << "Function in Black list: " << currFunc->getName() << "\n");
            return;
        }
        if (currCtx->checkRecursive(I)) {
            DEBUG_CALLINST(dbgs() << "Recursive found: " << I << "\n");
            return;
        }

        if (divein) {
            assert(!currFunc->isDeclaration());
            for (auto cb: disabledcallbacks) {
                cb->enabled = false;
            }
            auto parentCtx = pushContext(I, currFunc);
            for (auto &currCallback: allCallbacks) {
                if (currCallback->enabled) {
                    currCallback->setupChildContext(I, parentCtx);
                }
            }
            analyze(*currFunc);
            auto childCtx = popContext();
            for (auto &currCallback: allCallbacks) {
                if (currCallback->enabled) {
                    currCallback->stitchChildContext(I, childCtx);
                }
            }
            for (auto cb: disabledcallbacks) {
                cb->enabled = true;
            }
        }
    }
};

#endif  // GLOBALVISITOR_H
