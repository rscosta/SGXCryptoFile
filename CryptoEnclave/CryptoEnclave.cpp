#include "CryptoEnclave_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"
#include <string.h>

static sgx_aes_gcm_128bit_key_t key = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

void sgxDecryptFile(unsigned char *encMessageIn, size_t len, unsigned char *decMessageOut, size_t lenOut)
{
	uint8_t *encMessage = (uint8_t *) encMessageIn;
	uint8_t p_dst[lenOut];
        sgx_status_t ret;

        printDebug("INIT ENCLAVE DECRYPTION...");

	ret = sgx_rijndael128GCM_decrypt(
		&key,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		lenOut,
		p_dst,
		encMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) encMessage);

	if(ret == SGX_SUCCESS) printDebug("DECRYPT RESULT: SGX_SUCCESS");
	if(ret == SGX_ERROR_INVALID_PARAMETER) printDebug("DECRYPT RESULT: SGX_ERROR_INVALID_PARAMETER");
	if(ret == SGX_ERROR_OUT_OF_MEMORY) printDebug("DECRYPT RESULT: SGX_ERROR_OUT_OF_MEMORY");
	if(ret == SGX_ERROR_UNEXPECTED) printDebug("DECRYPT RESULT: SGX_ERROR_UNEXPECTED");

	memcpy(decMessageOut, p_dst, lenOut);
}

void sgxEncryptFile(unsigned char *decMessageIn, size_t len, unsigned char *encMessageOut, size_t lenOut)
{
	uint8_t *origMessage = (uint8_t *) decMessageIn;
	uint8_t p_dst[lenOut];
        sgx_status_t ret;

        printDebug("INIT ENCLAVE ENCRYPTION...");

	// Generate the IV (nonce)
	ret = sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

	if(ret == SGX_SUCCESS) printDebug("RAND RESULT: SGX_SUCCESS");
	if(ret == SGX_ERROR_INVALID_PARAMETER) printDebug("RAND RESULT: SGX_ERROR_INVALID_PARAMETER");
	if(ret == SGX_ERROR_UNEXPECTED) printDebug("RAND RESULT: SGX_ERROR_UNEXPECTED");

	ret = sgx_rijndael128GCM_encrypt(
		&key,
		origMessage, len, 
		p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst));	
	
	if(ret == SGX_SUCCESS) printDebug("ENCRYPT RESULT: SGX_SUCCESS");
	if(ret == SGX_ERROR_INVALID_PARAMETER) printDebug("ENCRYPT RESULT: SGX_ERROR_INVALID_PARAMETER");
	if(ret == SGX_ERROR_OUT_OF_MEMORY) printDebug("ENCRYPT RESULT: SGX_ERROR_OUT_OF_MEMORY");
	if(ret == SGX_ERROR_UNEXPECTED) printDebug("ENCRYPT RESULT: SGX_ERROR_UNEXPECTED");

        memcpy(encMessageOut,p_dst,lenOut);
}
