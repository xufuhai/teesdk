#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_enclave_create_report_t {
	uint32_t ms_retval;
	const sgx_target_info_t* ms_p_qe3_target;
	sgx_report_t* ms_p_report;
} ms_enclave_create_report_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t enclave_create_report(sgx_enclave_id_t eid, uint32_t* retval, const sgx_target_info_t* p_qe3_target, sgx_report_t* p_report)
{
	sgx_status_t status;
	ms_enclave_create_report_t ms;
	ms.ms_p_qe3_target = p_qe3_target;
	ms.ms_p_report = p_report;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

