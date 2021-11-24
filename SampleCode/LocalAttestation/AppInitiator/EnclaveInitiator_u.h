#ifndef ENCLAVEINITIATOR_U_H__
#define ENCLAVEINITIATOR_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_eid.h"
#include "datatypes.h"
#include "dh_session_protocol.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SESSION_REQUEST_OCALL_DEFINED__
#define SESSION_REQUEST_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, session_request_ocall, (sgx_dh_msg1_t* dh_msg1, uint32_t* session_id));
#endif
#ifndef EXCHANGE_REPORT_OCALL_DEFINED__
#define EXCHANGE_REPORT_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id));
#endif
#ifndef SEND_REQUEST_OCALL_DEFINED__
#define SEND_REQUEST_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, send_request_ocall, (uint32_t session_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size));
#endif
#ifndef END_SESSION_OCALL_DEFINED__
#define END_SESSION_OCALL_DEFINED__
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, end_session_ocall, (uint32_t session_id));
#endif

sgx_status_t test_create_session(sgx_enclave_id_t eid, uint32_t* retval);
sgx_status_t test_message_exchange(sgx_enclave_id_t eid, uint32_t* retval);
sgx_status_t test_close_session(sgx_enclave_id_t eid, uint32_t* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
