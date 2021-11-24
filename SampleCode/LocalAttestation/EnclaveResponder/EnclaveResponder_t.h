#ifndef ENCLAVERESPONDER_T_H__
#define ENCLAVERESPONDER_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_eid.h"
#include "datatypes.h"
#include "../Include/dh_session_protocol.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

uint32_t session_request(sgx_dh_msg1_t* dh_msg1, uint32_t* session_id);
uint32_t exchange_report(sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id);
uint32_t generate_response(secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size, uint32_t session_id);
uint32_t end_session(uint32_t session_id);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
