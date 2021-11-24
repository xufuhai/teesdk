#include "EnclaveInitiator_u.h"
#include <errno.h>

typedef struct ms_test_create_session_t {
	uint32_t ms_retval;
} ms_test_create_session_t;

typedef struct ms_test_message_exchange_t {
	uint32_t ms_retval;
} ms_test_message_exchange_t;

typedef struct ms_test_close_session_t {
	uint32_t ms_retval;
} ms_test_close_session_t;

typedef struct ms_session_request_ocall_t {
	uint32_t ms_retval;
	sgx_dh_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
} ms_session_request_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	uint32_t ms_retval;
	sgx_dh_msg2_t* ms_dh_msg2;
	sgx_dh_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
} ms_exchange_report_ocall_t;

typedef struct ms_send_request_ocall_t {
	uint32_t ms_retval;
	uint32_t ms_session_id;
	secure_message_t* ms_req_message;
	size_t ms_req_message_size;
	size_t ms_max_payload_size;
	secure_message_t* ms_resp_message;
	size_t ms_resp_message_size;
} ms_send_request_ocall_t;

typedef struct ms_end_session_ocall_t {
	uint32_t ms_retval;
	uint32_t ms_session_id;
} ms_end_session_ocall_t;

static sgx_status_t SGX_CDECL EnclaveInitiator_session_request_ocall(void* pms)
{
	ms_session_request_ocall_t* ms = SGX_CAST(ms_session_request_ocall_t*, pms);
	ms->ms_retval = session_request_ocall(ms->ms_dh_msg1, ms->ms_session_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveInitiator_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_dh_msg2, ms->ms_dh_msg3, ms->ms_session_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveInitiator_send_request_ocall(void* pms)
{
	ms_send_request_ocall_t* ms = SGX_CAST(ms_send_request_ocall_t*, pms);
	ms->ms_retval = send_request_ocall(ms->ms_session_id, ms->ms_req_message, ms->ms_req_message_size, ms->ms_max_payload_size, ms->ms_resp_message, ms->ms_resp_message_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveInitiator_end_session_ocall(void* pms)
{
	ms_end_session_ocall_t* ms = SGX_CAST(ms_end_session_ocall_t*, pms);
	ms->ms_retval = end_session_ocall(ms->ms_session_id);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[4];
} ocall_table_EnclaveInitiator = {
	4,
	{
		(void*)EnclaveInitiator_session_request_ocall,
		(void*)EnclaveInitiator_exchange_report_ocall,
		(void*)EnclaveInitiator_send_request_ocall,
		(void*)EnclaveInitiator_end_session_ocall,
	}
};
sgx_status_t test_create_session(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_test_create_session_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_EnclaveInitiator, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t test_message_exchange(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_test_message_exchange_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_EnclaveInitiator, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t test_close_session(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_test_close_session_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_EnclaveInitiator, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

