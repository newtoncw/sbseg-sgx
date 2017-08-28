#include "stdio.h"
#include "sgx_urts.h"
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "Enclave1_u.h" // generated by sgx_edger8r
#include "Enclave2_u.h" // generated by sgx_edger8r

#define TOKEN_FILENAME   "enclave.token"
#define ENCLAVE1_FILENAME "enclave1.signed.so"
#define ENCLAVE2_FILENAME "enclave2.signed.so"
#define MAX_PATH FILENAME_MAX

void printSGXError(sgx_status_t status);

int main(int argc, char *argv[]){
    /* Initialize the enclave */
    char token_path[MAX_PATH] = {'\0'};
    sgx_enclave_id_t e1id = 0, e2id;
    sgx_launch_token_t token1 = {0}, token2 = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;

    ret = sgx_create_enclave(ENCLAVE1_FILENAME, SGX_DEBUG_FLAG, &token1, &updated, &e1id, NULL);
    if(ret != SGX_SUCCESS){
        printf("Erro ao criar Enclave 1");
        return -1;
    }

    updated = 0;

    ret = sgx_create_enclave(ENCLAVE2_FILENAME, SGX_DEBUG_FLAG, &token2, &updated, &e2id, NULL);
    if(ret != SGX_SUCCESS){
        printf("Erro ao criar Enclave 2");
        return -1;
    }

    ret = Enclave1_ecall_send_message(e1id, e1id, e2id, "Teste Mensagem");

    if(ret != SGX_SUCCESS){
        printf("Erro ao enviar mensagem\n");
        printSGXError(ret);
        return -1;
    }

    sgx_destroy_enclave(e1id);
    sgx_destroy_enclave(e2id);

    return 0;
}

void printSGXError(sgx_status_t status){
    switch(status){
        case SGX_ERROR_UNEXPECTED:
            printf("SGX_ERROR_UNEXPECTED: Unexpected error.\n");
            break;
        case SGX_ERROR_INVALID_PARAMETER:
            printf("SGX_ERROR_INVALID_PARAMETER: The parameter is incorrect\n");
            break;
        case SGX_ERROR_OUT_OF_MEMORY:
            printf("SGX_ERROR_OUT_OF_MEMORY: Not enough memory is available to complete this operation\n");
            break;
        case SGX_ERROR_ENCLAVE_LOST:
            printf("SGX_ERROR_ENCLAVE_LOST: Enclave lost after power transition or used in child process created by linux:fork()\n");
            break;
        case SGX_ERROR_INVALID_STATE:
            printf("SGX_ERROR_INVALID_STATE: SGX API is invoked in incorrect order or state\n");
            break;
        case SGX_ERROR_INVALID_FUNCTION:
            printf("SGX_ERROR_INVALID_FUNCTION: The ecall/ocall index is invalid\n");
            break;
        case SGX_ERROR_OUT_OF_TCS:
            printf("SGX_ERROR_OUT_OF_TCS: The enclave is out of TCS\n");
            break;
        case SGX_ERROR_ENCLAVE_CRASHED:
            printf("SGX_ERROR_ENCLAVE_CRASHED: The enclave is crashed\n");
            break;
        case SGX_ERROR_ECALL_NOT_ALLOWED:
            printf("SGX_ERROR_ECALL_NOT_ALLOWED: The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization\n");
            break;
        case SGX_ERROR_OCALL_NOT_ALLOWED:
            printf("SGX_ERROR_OCALL_NOT_ALLOWED: The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling\n");
            break;
        case SGX_ERROR_STACK_OVERRUN:
            printf("SGX_ERROR_STACK_OVERRUN: The enclave is running out of stack\n");
            break;
        case SGX_ERROR_UNDEFINED_SYMBOL:
            printf("SGX_ERROR_UNDEFINED_SYMBOL: The enclave image has undefined symbol.\n");
            break;
        case SGX_ERROR_INVALID_ENCLAVE:
            printf("SGX_ERROR_INVALID_ENCLAVE: The enclave image is not correct.\n");
            break;
        case SGX_ERROR_INVALID_ENCLAVE_ID:
            printf("SGX_ERROR_INVALID_ENCLAVE_ID: The enclave id is invalid\n");
            break;
        case SGX_ERROR_INVALID_SIGNATURE:
            printf("SGX_ERROR_INVALID_SIGNATURE: The signature is invalid\n");
            break;
        case SGX_ERROR_NDEBUG_ENCLAVE:
            printf("SGX_ERROR_NDEBUG_ENCLAVE: The enclave is signed as product enclave, and can not be created as debuggable enclave.\n");
            break;
        case SGX_ERROR_OUT_OF_EPC:
            printf("SGX_ERROR_OUT_OF_EPC: Not enough EPC is available to load the enclave\n");
            break;
        case SGX_ERROR_NO_DEVICE:
            printf("SGX_ERROR_NO_DEVICE: Can't open SGX device\n");
            break;
        case SGX_ERROR_MEMORY_MAP_CONFLICT:
            printf("SGX_ERROR_MEMORY_MAP_CONFLICT: Page mapping failed in driver\n");
            break;
        case SGX_ERROR_INVALID_METADATA:
            printf("SGX_ERROR_INVALID_METADATA: The metadata is incorrect.\n");
            break;
        case SGX_ERROR_DEVICE_BUSY:
            printf("SGX_ERROR_DEVICE_BUSY: Device is busy, mostly EINIT failed.\n");
            break;
        case SGX_ERROR_INVALID_VERSION:
            printf("SGX_ERROR_INVALID_VERSION: Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform.\n");
            break;
        case SGX_ERROR_MODE_INCOMPATIBLE:
            printf("SGX_ERROR_MODE_INCOMPATIBLE: The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS.\n");
            break;
        case SGX_ERROR_ENCLAVE_FILE_ACCESS:
            printf("SGX_ERROR_ENCLAVE_FILE_ACCESS: Can't open enclave file.\n");
            break;
        case SGX_ERROR_INVALID_MISC:
            printf("SGX_ERROR_INVALID_MISC: The MiscSelct/MiscMask settings are not correct.\n");
            break;
        case SGX_ERROR_MAC_MISMATCH:
            printf("SGX_ERROR_MAC_MISMATCH: Indicates verification error for reports, sealed datas, etc\n");
            break;
        case SGX_ERROR_INVALID_ATTRIBUTE:
            printf("SGX_ERROR_INVALID_ATTRIBUTE: The enclave is not authorized\n");
            break;
        case SGX_ERROR_INVALID_CPUSVN:
            printf("SGX_ERROR_INVALID_CPUSVN: The cpu svn is beyond platform's cpu svn value\n");
            break;
        case SGX_ERROR_INVALID_ISVSVN:
            printf("SGX_ERROR_INVALID_ISVSVN: The isv svn is greater than the enclave's isv svn\n");
            break;
        case SGX_ERROR_INVALID_KEYNAME:
            printf("SGX_ERROR_INVALID_KEYNAME: The key name is an unsupported value\n");
            break;
        case SGX_ERROR_SERVICE_UNAVAILABLE:
            printf("SGX_ERROR_SERVICE_UNAVAILABLE: Indicates aesm didn't response or the requested service is not supported\n");
            break;
        case SGX_ERROR_SERVICE_TIMEOUT:
            printf("SGX_ERROR_SERVICE_TIMEOUT: The request to aesm time out\n");
            break;
        case SGX_ERROR_AE_INVALID_EPIDBLOB:
            printf("SGX_ERROR_AE_INVALID_EPIDBLOB: Indicates epid blob verification error\n");
            break;
        case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
            printf("SGX_ERROR_SERVICE_INVALID_PRIVILEGE: Enclave has no privilege to get launch token\n");
            break;
        case SGX_ERROR_EPID_MEMBER_REVOKED:
            printf("SGX_ERROR_EPID_MEMBER_REVOKED: The EPID group membership is revoked.\n");
            break;
        case SGX_ERROR_UPDATE_NEEDED:
            printf("SGX_ERROR_UPDATE_NEEDED: SGX needs to be updated\n");
            break;
        case SGX_ERROR_NETWORK_FAILURE:
            printf("SGX_ERROR_NETWORK_FAILURE: Network connecting or proxy setting issue is encountered\n");
            break;
        case SGX_ERROR_AE_SESSION_INVALID:
            printf("SGX_ERROR_AE_SESSION_INVALID: Session is invalid or ended by server\n");
            break;
        case SGX_ERROR_BUSY:
            printf("SGX_ERROR_BUSY: The requested service is temporarily not availabe\n");
            break;
        case SGX_ERROR_MC_NOT_FOUND:
            printf("SGX_ERROR_MC_NOT_FOUND: The Monotonic Counter doesn't exist or has been invalided\n");
            break;
        case SGX_ERROR_MC_NO_ACCESS_RIGHT:
            printf("SGX_ERROR_MC_NO_ACCESS_RIGHT: Caller doesn't have the access right to specified VMC\n");
            break;
        case SGX_ERROR_MC_USED_UP:
            printf("SGX_ERROR_MC_USED_UP: Monotonic counters are used out\n");
            break;
        case SGX_ERROR_MC_OVER_QUOTA:
            printf("SGX_ERROR_MC_OVER_QUOTA: Monotonic counters exceeds quota limitation\n");
            break;
        case SGX_ERROR_KDF_MISMATCH:
            printf("SGX_ERROR_KDF_MISMATCH: Key derivation function doesn't match during key exchange\n");
            break;
    }
}