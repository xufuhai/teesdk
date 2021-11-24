#include "EnclaveResponder_u.h"
#include <errno.h>

typedef struct ms_session_request_t {
	uint32_t ms_retval;
	sgx_dh_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
} ms_session_request_t;

typedef struct ms_exchange_report_t {
	uint32_t ms_retval;
	sgx_dh_msg2_t* ms_dh_msg2;
	sgx_dh_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
} ms_exchange_report_t;

typedef struct ms_generate_response_t {
	uint32_t ms_retval;
	secure_message_t* ms_req_message;
	size_t ms_req_message_size;
	size_t ms_max_payload_size;
	secure_message_t* ms_resp_message;
	size_t ms_resp_message_size;
	uint32_t ms_session_id;
} ms_generate_response_t;

typedef struct ms_end_session_t {
	uint32_t ms_retval;
	uint32_t ms_session_id;
} ms_end_session_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_EnclaveResponder = {
	0,
	{ NULL },
};
sgx_status_t session_request(sgx_enclave_id_t eid, uint32_t* retval, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{
	sgx_status_t status;
	ms_session_request_t ms;
	ms.ms_dh_msg1 = dh_msg1;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 0, &ocall_table_EnclaveResponder, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t exchange_report(sgx_enclave_id_t eid, uint32_t* retval, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id)
{
	sgx_status_t status;
	ms_exchange_report_t ms;
	ms.ms_dh_msg2 = dh_msg2;
	ms.ms_dh_msg3 = dh_msg3;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 1, &ocall_table_EnclaveResponder, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t generate_response(sgx_enclave_id_t eid, uint32_t* retval, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size, uint32_t session_id)
{
	sgx_status_t status;
	ms_generate_response_t ms;
	ms.ms_req_message = req_message;
	ms.ms_req_message_size = req_message_size;
	ms.ms_max_payload_size = max_payload_size;
	ms.ms_resp_message = resp_message;
	ms.ms_resp_message_size = resp_message_size;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 2, &ocall_table_EnclaveResponder, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t end_session(sgx_enclave_id_t eid, uint32_t* retval, uint32_t session_id)
{
	sgx_status_t status;
	ms_end_session_t ms;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 3, &ocall_table_EnclaveResponder, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

