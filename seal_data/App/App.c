#include "stdio.h"
#include "string.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "Enclave_u.h" // Gerado pelo Edger8r

#define ENCLAVE_FILENAME "enclave.signed.so"

int main(int argc, char *argv[])
{
    char *data = "Hello World!!!";
    uint8_t *sealed_data, *unsealed_data;
    uint32_t data_size = strlen(data), sealed_data_size, unsealed_data_size, i;
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);

    if (ret != SGX_SUCCESS) {
        printf("Erro na inicializacao do enclave ...\n");
        return -1; 
    }

    ret = ecall_get_sealed_data_size(eid, data_size, &sealed_data_size);

    if (ret != SGX_SUCCESS) {
        printf("Erro ao calcular o tamanho dos dados selados.\n");
        return -1; 
    }

    sealed_data = (uint8_t*) malloc(sealed_data_size);

    ret = ecall_seal_data(eid, (uint8_t*)data, data_size, sealed_data, sealed_data_size);

    if (ret != SGX_SUCCESS) {
        printf("Erro ao selar dados ...\n");
        return -1; 
    } else {
        printf("Dados selados: \n");

        for(i = 0; i < sealed_data_size; i++)
            printf("%02x ", sealed_data[i]);

        printf("\n");
    }

    ret = ecall_get_unsealed_data_size(eid, sealed_data, sealed_data_size, &unsealed_data_size);

    if (ret != SGX_SUCCESS) {
        printf("Erro ao calcular o tamanho dos dados abertos.\n");
        return -1; 
    }

    unsealed_data = (uint8_t*) malloc(unsealed_data_size);

    ret = ecall_unseal_data(eid, sealed_data, sealed_data_size, unsealed_data, unsealed_data_size);

    if (ret != SGX_SUCCESS) {
        printf("Erro ao abrir dados ...\n");
        return -1; 
    } else {
        printf("Dados abertos: \n%s\n", (char*)unsealed_data);
    }

    if(sgx_destroy_enclave(eid) != SGX_SUCCESS) {
        printf("ERRO ao destruir o enclave.\n");
        return -1;
    }

    return 0;
}
