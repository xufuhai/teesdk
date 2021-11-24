#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_enclave_create_report_t {
	uint32_t ms_retval;
	const sgx_target_info_t* ms_p_qe3_target;
	sgx_report_t* ms_p_report;
} ms_enclave_create_report_t;

static sgx_status_t SGX_CDECL sgx_enclave_create_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_create_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_create_report_t* ms = SGX_CAST(ms_enclave_create_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgx_target_info_t* _tmp_p_qe3_target = ms->ms_p_qe3_target;
	size_t _len_p_qe3_target = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_p_qe3_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_qe3_target, _len_p_qe3_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_qe3_target != NULL && _len_p_qe3_target != 0) {
		_in_p_qe3_target = (sgx_target_info_t*)malloc(_len_p_qe3_target);
		if (_in_p_qe3_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_qe3_target, _len_p_qe3_target, _tmp_p_qe3_target, _len_p_qe3_target)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}

	ms->ms_retval = enclave_create_report((const sgx_target_info_t*)_in_p_qe3_target, _in_p_report);
	if (_in_p_report) {
		if (memcpy_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_qe3_target) free(_in_p_qe3_target);
	if (_in_p_report) free(_in_p_report);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_enclave_create_report, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


