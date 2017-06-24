#include <string.h>

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"

#include "getopt.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "cpuidh.h" //benchmark

#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12

#define VERSION   "1.1.170624"
#define AUTHOR   "Ricardo Costa"

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

    start_time();

    sgxEncryptFile(eid, message, fsize, encMessage, encMessageLen);

    end_time();

    encMessage[encMessageLen] = '\0';

    fwrite(encMessage, encMessageLen, 1, ofp);

    free(encMessage);
    free(message);

    fclose(ifp);
    fclose(ofp);

    printf("[APP ENCRYPT] Encryption file (%s) created!\n",output);
    printf("[APP ENCRYPT] Final encryption time: %6.6f seconds.\n", secs);
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

    start_time();

    sgxDecryptFile(eid,message,fsize,decMessage,decMessageLen);

    end_time();

    decMessage[decMessageLen] = '\0';

    fwrite(decMessage, decMessageLen, 1, ofp);

    free(decMessage);
    free(message);

    fclose(ifp);
    fclose(ofp);

    printf("[APP DECRYPT] Decryption file (%s) created!\n",output);
    printf("[APP DECRYPT] Final decryption time: %6.6f seconds.\n", secs);
}

void printDebug(const char *buf)

{
    printf("ENCLAVE: %s\n", buf);
}

void printAppUsage()
{
    printf("\nSgxCryptoFile - App for Encrypting and Decrypting Files using Intel SGX. Version:%s Author:%s\n", VERSION, AUTHOR);  
    printf("Usage: sgxCryptoFile [OPTIONS] [FILE]\n\n");
    printf("Options:\n");
    printf(" -d\tdecryption mode enabled\n");
    printf(" -e\tencryption mode enabled\n");
    printf(" -i\tinput file\n");
    printf("Example (Encryption): sgxCryptoFile -e -i file.txt (Output: [FILE].enc)\n");
    printf("Example (Decryption): sgxCryptoFile -d -i file.txt (Output: [FILE].dec)\n\n");
}

int main(int argc, char *argv[])
{
    int option = 0;
    int mode = 0;
    char fileName[256];
    char encFileName[256];
    char decFileName[256];
    
    // Specifying the expected options 
    while ((option = getopt(argc, argv,"edi:")) != -1) {
        switch (option) {
	     case 'e' : 
	                mode = 1; /*Encryption enabled */
                 break;
             case 'd' : 
	                mode = 2; /*Decryption enabled */
                break;
             case 'i' : 
			if(optarg == NULL)
			  exit(EXIT_FAILURE);
			  
			  strncpy(fileName, optarg, 256); // filename to encrypted/decrypted 
                 break;
             default: printAppUsage(); 
                 exit(EXIT_FAILURE);
        }
    }
    
    //Check if it is invalid mode
    if (mode == 0)
    {
	printAppUsage();
	exit(EXIT_FAILURE);
    }
      
    if(mode ==1)
    {
	strcpy(encFileName, fileName);
	strcat(encFileName, ".enc");
    }
    else
    {
	strcpy(decFileName, fileName);
	strcat(decFileName, ".dec");
    }

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
	exit(EXIT_FAILURE);
    }

    if(mode ==1)
    {
	//Encrypt a file
	encryptFile(eid, fileName, encFileName);
    }
    else
    {
      	//Decrypt a file
	decryptFile(eid, encFileName, decFileName);
    }
    
    //Destroy Enclave
    sgx_destroy_enclave(eid);
	
    return 0;
}

