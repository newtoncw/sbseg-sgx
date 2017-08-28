#include "string.h"
#include "sgx_tcrypto.h"
#include "Enclave_t.h" //Gerado pelo Edger8r

void ecall_teste(char *c) {
    sgx_status_t ret;
    sgx_sha256_hash_t hash;
    
    ret = sgx_sha256_msg((const uint8_t *)c, strlen(c), &hash);

    if (ret == SGX_SUCCESS) {
    	ocall_print("sgx_sha256_msg SUCESSO");
    	ocall_print((char*)hash);
    } else {
    	ocall_print("sgx_sha256_msg ERRO");
    }
}
