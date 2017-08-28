#include "stdio.h"
#include "string.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "Enclave_u.h" //Gerado pelo Edger8r

#define ENCLAVE_FILENAME "enclave.signed.so"

int main(int argc, char *argv[]) {
    char *data = "Hello World!";
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    
    if (ret != SGX_SUCCESS) {
        printf("Erro na inicializacao do enclave ...\n");
        return -1;
    }

    if (ecall_teste(eid, data) != SGX_SUCCESS) {
        printf("ERRO na execucao da ecall ...\n");
    } else {
        printf("SUCESSO na execucao da ecall ...\n");
    }

    if(sgx_destroy_enclave(eid) != SGX_SUCCESS) {
        printf("ERRO ao destruir o enclave.\n");
        return -1;
    }

    return 0;
}
