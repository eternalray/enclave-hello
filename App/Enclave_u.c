#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_save_string_t {
	char* ms_string;
} ms_save_string_t;

typedef struct ms_ocall_print_t {
	char* ms_str;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print,
	}
};
sgx_status_t save_string(sgx_enclave_id_t eid, const char* string)
{
	sgx_status_t status;
	ms_save_string_t ms;
	ms.ms_string = (char*)string;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

