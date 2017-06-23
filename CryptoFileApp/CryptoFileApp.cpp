#include <string.h>

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"

#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12

#define ENCLAVE_FILE "CryptoEnclave.signed.so"

int encryptFile(sgx_enclave_id_t eid, const char* input, const char* output)
{
    FILE *ifp = NULL;
    FILE *ofp = NULL;
    int nread = 0;
    
    if((ifp = fopen(input, "rb")) == NULL)
    {
      printf("[APP ENCRYPT] Input File %s not found!\n",input);
      return -1;
    }

    if((ofp = fopen(output, "wb")) == NULL)
    {
      printf("[APP ENCRYPT] Error while creating output File %s\n",output);
      fclose(ifp);
      return -1;
    }

    fseek(ifp, 0, SEEK_END);
    long fsize = ftell(ifp);
    fseek(ifp, 0, SEEK_SET);  //same as rewind(f);
    unsigned char *message = (unsigned char*)malloc(fsize + 1);
    size_t readRes = fread(message, fsize, 1, ifp);
    size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + fsize); 
    unsigned char *encMessage = (unsigned char *) malloc((encMessageLen+1)*sizeof(unsigned char));

    sgxEncryptFile(eid, message, fsize, encMessage, encMessageLen);
    encMessage[encMessageLen] = '\0';

    fwrite(encMessage, encMessageLen, 1, ofp);

    free(encMessage);
    free(message);

    fclose(ifp);
    fclose(ofp);

    printf("[APP ENCRYPT] Encryption file (%s) created!\n",output);
}

int decryptFile(sgx_enclave_id_t eid, const char* input, const char* output)
{
    FILE *ifp = NULL;
    FILE *ofp = NULL;
    int nread = 0;
    
    if((ifp = fopen(input, "rb")) == NULL)
    {
      printf("[APP DECRYPT] Input File %s not found!\n",input);
      return -1;
    }

    if((ofp = fopen(output, "wb")) == NULL)
    {
      printf("[APP DECRYPT] Error while creating output File %s\n",output);
      fclose(ifp);
      return -1;
    }

    fseek(ifp, 0, SEEK_END);
    long fsize = ftell(ifp);
    fseek(ifp, 0, SEEK_SET);  //same as rewind(f);
    unsigned char *message = (unsigned char*)malloc(fsize + 1);
    size_t readRes = fread(message, fsize, 1, ifp);
    size_t decMessageLen = fsize - (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE);
    unsigned char *decMessage = (unsigned char *) malloc((decMessageLen+1)*sizeof(unsigned char));
	
    sgxDecryptFile(eid,message,fsize,decMessage,decMessageLen);
    decMessage[decMessageLen] = '\0';

    fwrite(decMessage, decMessageLen, 1, ofp);

    free(decMessage);
    free(message);

    fclose(ifp);
    fclose(ofp);

    printf("[APP DECRYPT] Decryption file (%s) created!\n",output);
}

void printDebug(const char *buf)

{
    printf("ENCLAVE: %s\n", buf);
}

int main(int argc, char *argv[])
{
	if((argv[1] == NULL) && (argc != 2))
	{
	  printf("sgxCryptoFile - SGX App for Encrypting and Decrypting Files\n");
	  printf("Usage: sgxCryptoFile [FILE]\n\n");
	  printf("Output: [FILE].enc and [FILE].dec\n");
	  return 0;
	}  
	
	char fileName[256];
	char encFileName[256];
	char decFileName[256];

	strcpy(fileName, argv[1]);

	strcpy(encFileName, fileName);
	strcat(encFileName, ".enc");

	strcpy(decFileName, fileName);
	strcat(decFileName, ".dec");
		
	// Setup enclave 
	sgx_enclave_id_t eid;
	sgx_status_t ret;
	sgx_launch_token_t token = { 0 };
	int token_updated = 0;
	
	//Init enclave
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &token_updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("sgx_create_enclave failed: %#x\n", ret);
		return 1;
	}

	//Encrypt a file
	encryptFile(eid, fileName, encFileName);

	//Decrypt a file
	decryptFile(eid, encFileName, decFileName);
	
	//Destroy Enclave
	sgx_destroy_enclave(eid);
	
	return 0;
}

