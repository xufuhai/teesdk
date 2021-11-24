#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_report.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t enclave_create_report(sgx_enclave_id_t eid, uint32_t* retval, const sgx_target_info_t* p_qe3_target, sgx_report_t* p_report);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
