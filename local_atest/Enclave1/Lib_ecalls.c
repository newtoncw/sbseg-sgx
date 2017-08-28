#include "sgx_eid.h"
#include "sgx_report.h"
#include "sgx_eid.h"
#include "sgx_ecp_types.h"
#include "sgx_dh.h"
#include "sgx_tseal.h"
#include "stdlib.h"
#include "string.h"
#include "Enclave1_t.h"

sgx_key_128bit_t session_dh_aek;
sgx_dh_session_t sgx_dh_session;

sgx_status_t Enclave1_create_session(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id) {
    sgx_status_t status = SGX_SUCCESS;
    sgx_key_128bit_t dh_aek;
    sgx_dh_msg1_t dh_msg1;  //Diffie-Hellman Message 1
    sgx_dh_msg2_t dh_msg2;  //Diffie-Hellman Message 2
    sgx_dh_msg3_t dh_msg3;  //Diffie-Hellman Message 3
    sgx_dh_session_enclave_identity_t responder_identity;

    status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if(status != SGX_SUCCESS) {
        return status;
    }

    status = Enclave1_ocall_session_request(dest_enclave_id, &dh_msg1);
    if (status != SGX_SUCCESS) {
        return status;
    }

    status = sgx_dh_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if (status != SGX_SUCCESS) {
        return status;
    }

    status = Enclave1_ocall_exchange_report(dest_enclave_id, &dh_msg2, &dh_msg3, &dh_aek);
    if (status != SGX_SUCCESS) {
        return status;
    }

    status = sgx_dh_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if (status != SGX_SUCCESS) {
        return status;
    }

    memcpy(&session_dh_aek, dh_aek, sizeof(sgx_key_128bit_t));

    return SGX_SUCCESS;
}

void Enclave1_ecall_send_message(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, const char* message) {
    sgx_status_t status;
    uint32_t src_len = strlen(message);
    uint8_t p_dest2[src_len];
    sgx_aes_gcm_data_t* secure_message;
    size_t message_size;

    status = Enclave1_create_session(src_enclave_id, dest_enclave_id);
    if(status != SGX_SUCCESS) {
        ocall_print("Enclave1_create_session ERRO");
        return;
    }

    message_size = sizeof(sgx_aes_gcm_data_t) + src_len;
    secure_message = (sgx_aes_gcm_data_t*)malloc(message_size);
    secure_message->payload_size = src_len;

    status = sgx_rijndael128GCM_encrypt(&session_dh_aek, (uint8_t*)message, src_len, secure_message->payload, secure_message->reserved, sizeof(secure_message->reserved), NULL, 0, &(secure_message->payload_tag));
    if(status != SGX_SUCCESS) {
        ocall_print("sgx_rijndael128GCM_encrypt ERRO");
        return;
    }

    status = Enclave1_ocall_send_request(dest_enclave_id, secure_message, message_size);
    if(status != SGX_SUCCESS) {
        ocall_print("ERRO ao enviar mensagem");
        return;
    }
}
