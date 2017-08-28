#include "sgx_eid.h"
#include "sgx_report.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_dh.h"
#include "sgx_tseal.h"
#include "string.h"
#include "stdlib.h"
#include "Enclave2_t.h"

sgx_key_128bit_t session_dh_aek;
sgx_dh_session_t sgx_dh_session;

void Enclave2_ecall_session_request(sgx_dh_msg1_t *dh_msg1) {
    sgx_status_t status = SGX_SUCCESS;

    if(!dh_msg1) {
        ocall_print("dh_msg1 INVALIDA!");
        return;
    }

    ocall_print("Enclave 2 sgx_dh_init_session");
    status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(status != SGX_SUCCESS) {
        ocall_print("ERRO!");
        return;
    }

    ocall_print("Enclave 2 sgx_dh_responder_gen_msg1");
    status = sgx_dh_responder_gen_msg1(dh_msg1, &sgx_dh_session);
    if(status != SGX_SUCCESS) {
        ocall_print("ERRO!");
        return;
    }
}

void Enclave2_ecall_exchange_report(sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, sgx_key_128bit_t *dh_aek) {
    sgx_dh_session_enclave_identity_t initiator_identity;

    ocall_print("Enclave 2 sgx_dh_responder_proc_msg2");
    sgx_status_t status = sgx_dh_responder_proc_msg2(dh_msg2, dh_msg3, &sgx_dh_session, dh_aek, &initiator_identity);
    if(status != SGX_SUCCESS) {
        ocall_print("ERRO!");
        return;
    }

    memcpy(&session_dh_aek, dh_aek, sizeof(sgx_key_128bit_t));
}

void Enclave2_ecall_receive_message(sgx_aes_gcm_data_t* message, size_t message_size) {
    sgx_status_t status;
    uint8_t p_dest[message->payload_size];

    status = sgx_rijndael128GCM_decrypt(&session_dh_aek, message->payload, message->payload_size, p_dest, message->reserved, sizeof(message->reserved), NULL, 0, &(message->payload_tag));

    if(status != SGX_SUCCESS) {
        ocall_print("sgx_rijndael128GCM_decrypt ERRO");
    } else {
        ocall_print((char*)p_dest);
    }
}
