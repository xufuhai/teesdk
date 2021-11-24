#ifndef ENCLAVEINITIATOR_T_H__
#define ENCLAVEINITIATOR_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_eid.h"
#include "datatypes.h"
#include "dh_session_protocol.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

uint32_t test_create_session(void);
uint32_t test_message_exchange(void);
uint32_t test_close_session(void);

sgx_status_t SGX_CDECL session_request_ocall(uint32_t* retval, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id);
sgx_status_t SGX_CDECL exchange_report_ocall(uint32_t* retval, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id);
sgx_status_t SGX_CDECL send_request_ocall(uint32_t* retval, uint32_t session_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size);
sgx_status_t SGX_CDECL end_session_ocall(uint32_t* retval, uint32_t session_id);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
