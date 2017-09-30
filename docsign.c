/*
This program is implemented for digital signing and verifying of documents.
This ensures that a file is last edited and signed by the proper author.

Compile using:
-------------- 
gcc docsign.c -o docsign -lcrypto -lm

Execute using: (show help with: ./docsign )
--------------
First create keys with: ./docsign -createkeys
Then sign a document with: ./docsign -s DOCUMENT
Finally verify signature with: ./docsign -v DOCUMENT signature_64

Author: Antreas Dionysiou
Date created: 20/7/2017
Version: 1.0

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/sha.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <openssl/evp.h>
#include <string.h>
#include <openssl/bio.h>
#include <stdint.h>
#include <math.h>

/*This function is used to encode a given string in 'buffer' with length 
'length' and sets a pointer to the encoded string in 'b64text'*/
int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { 
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);
	//Ignore newlines - write everything in one line
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);
	*b64text=(*bufferPtr).data;
	return (0); //success
}

/*Calculates the length of a decoded string.*/
size_t calcDecodeLength(const char* b64input) { 
	size_t len = strlen(b64input),
		padding = 0;
	if (b64input[len-1] == '=' && b64input[len-2] == '=') 
		padding = 2;
	else if (b64input[len-1] == '=') 
		padding = 1;
	return (len*3)/4 - padding;
}

/*Decodes a given string in 'b64message' and places the result in 'buffer'. */
int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { 
	BIO *bio, *b64;
	int decodeLen = calcDecodeLength(b64message);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';
	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); 
	*length = BIO_read(bio, *buffer, strlen(b64message));
	BIO_free_all(bio);
	return (0); //success
}

/*Show this menu as help if ./docsign is issued in terminal.*/
int show_menu(){
  printf("\nAvailable commands to perform:\n");
  printf("------------------------------\n");
  printf("./docsign -createkeys\t\t(Create private and public key files.)\n");
  printf("./docsign -s <filename>\t\t(Compute, display and save signature of <filename> file to 'signature_64' file.)\n");
  printf("./docsign -v <filename> <signature_file>  (Verify that the signature of <filename> mathces <signature_file>.)\n\n");
  return 0;
}

//MAIN FUNCTION
int main(int argc, char * argv[]){
 
  /* Initializing OpenSSL */
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  
  if ((argc==1)&&(strcmp(argv[0],"./docsign")==0)){ //show help if ./docsign issued.
	show_menu();
  }
  else if ((argc==2)&&(strcmp(argv[0],"./docsign")==0)&&(strcmp(argv[1],"-createkeys")==0)){
	//create keys
	EVP_PKEY *pkey;
	pkey = EVP_PKEY_new();
	BIGNUM *bn;
	bn = BN_new();
	BN_set_word(bn, RSA_F4);
	RSA * rsa;
	rsa = RSA_new();
	RSA_generate_key_ex(rsa,2048, bn,NULL);
	EVP_PKEY_assign_RSA(pkey, rsa);

	//write two keys in files to load them when necessary.
	//first write public key.
	FILE * fp;
	fp = fopen("./public_key", "w");
	if(!PEM_write_RSAPublicKey(fp, rsa))
	{
   		printf("\n%s\n", "Error writing public key");
	}	
	fflush(fp);
	fclose(fp);
	//then write private key.
	fp = fopen("./private_key", "w");
	if(!PEM_write_RSAPrivateKey(fp, rsa, NULL, 0, 0, NULL, NULL))
	{
    		printf("\n%s\n", "Error writing private key");
	}
	fflush(fp);
	fclose(fp);
	printf("\nRSA Key files 'private_key' and 'public_key' created successfully!\n\n");
	//Both public and private keys are written in files till this point.
  }
  else if ((argc==3)&&(strcmp(argv[0],"./docsign")==0)&&(strcmp(argv[1],"-s")==0)){

	//Check if plain text file given exists.
	FILE * file;
	file = fopen(argv[2], "r");
	if (file){
   		//file exists and can be opened. 
   	fclose(file);
	}else{
   		//file doesn't exists or cannot be opened (es. you don't have access permission )
		printf("FILE GIVEN DOES NOT EXIST!!!\n");
		exit(0);
	}
	
	//First compute the hash value of file given.
	int i=0;
	file = fopen(argv[2], "rb");
   	if(!file) return -1;
    	unsigned char hash[SHA256_DIGEST_LENGTH];
    	SHA256_CTX sha256;
    	SHA256_Init(&sha256);
    	const int bufSize = 32768;
    	char *buffer = malloc(bufSize);
    	int bytesRead = 0;
    	if(!buffer) return ENOMEM;
    	while((bytesRead = fread(buffer, 1, bufSize, file)))
    	{
        	SHA256_Update(&sha256, buffer, bytesRead);
    	}
    	SHA256_Final(hash, &sha256);
    	unsigned char output[4000];
    	SHA256(hash, SHA256_DIGEST_LENGTH,output);
    	fclose(file);
    	free(buffer);
	int output_len=strlen(output);	//compute hash value length.

	//Second read the private key from private_key file.
	RSA * rsa_private_key = NULL;
	FILE * fp = fopen("./private_key", "rb");
	rsa_private_key = PEM_read_RSAPrivateKey(fp, NULL,NULL, NULL);
	fclose(fp); //close file.
	//Rsa private key is now in rsa_private_key structure.

	//Third compute and display the signature by encrypting allready computed hash value with RSA.
	unsigned char signature[40000]; //create a buffer to store signature.
	int signature_length=0;	 //variable to hold signature length.
	//encrypt(sign) hashed value with RSA.
	RSA_sign(NID_sha256,output,output_len ,signature, &signature_length, rsa_private_key);

	//Encode signature to base64 format.
	char* base64encoded;
	const unsigned char *signature_p=signature;
	Base64Encode(signature_p, signature_length, &base64encoded);

	//Write Base64 encoded signature to file 'signature_64' for later use.
	fp =fopen("./signature_64","w");
	fwrite(base64encoded,strlen(base64encoded),sizeof(char),fp);
	fflush(fp);
	fclose(fp);

	//Display the signature of the document in unsigned ints.
	printf("\nThe computed signature in base64 format is: \n", base64encoded);
	printf("-------------------------------------------\n");
	printf("%s\n",base64encoded);
	printf("-------------------------------------------\n");
	printf("The signature of the document is written(base64 format) in 'signature_64' file.\n\n");

  }
  else if ((argc==4)&&(strcmp(argv[0],"./docsign")==0)&&(strcmp(argv[1],"-v")==0)){
	//Check if plain text file given exists.
	FILE * file;
	file = fopen(argv[2], "r");
	if (file){
   		//file exists and can be opened 
   	fclose(file);
	}else{
   		//file doesn't exists or cannot be opened (es. you don't have access permission )
		printf("\nDOCUMENT TO BE VERIFIED DOES NOT EXIST!!!\n\n");
		exit(0);
	}

	//Check if signature file given exists.
	file = fopen(argv[3], "r");
	if (file){
   		//file exists and can be opened 
   	fclose(file);
	}else{
   		//file doesn't exists or cannot be opened (es. you don't have access permission )
		printf("\nSIGNATURE FILE GIVEN DOES NOT EXIST!!!\n\n");
		exit(0);
	}

	//First compute the hash value of file given.
	file = fopen(argv[2], "rb");
    	if(!file) return -1;
    	unsigned char hash[SHA256_DIGEST_LENGTH];
    	SHA256_CTX sha256;
    	SHA256_Init(&sha256);
    	const int bufSize = 32768;
    	char *buffer = malloc(bufSize);
    	int bytesRead = 0;
    	if(!buffer) return ENOMEM;
    	while((bytesRead = fread(buffer, 1, bufSize, file)))
    	{
        	SHA256_Update(&sha256, buffer, bytesRead);
    	}
    	SHA256_Final(hash, &sha256);
    	unsigned char output[4000];
    	SHA256(hash, SHA256_DIGEST_LENGTH,output);
    	fclose(file);
    	free(buffer);

	//Second read the public key from the public_key file.
	RSA * rsa_public_key = NULL;
	RSA_free(rsa_public_key);
	FILE * fp = fopen("./public_key", "r");
	rsa_public_key = PEM_read_RSAPublicKey(fp, NULL,NULL, NULL);
	fclose(fp); //close file.
	//Rsa public key is now in rsa_public_key structure.

	//Third read the signature encoded in base64 file from file given.
	fp =fopen(argv[3],"r");
	char signature_base64[40000];
	fread(signature_base64, sizeof(char), 40000, fp);

	//Fourth decode the base64 signature read in previous step.
  	unsigned char* base64DecodeOutput;
  	size_t test;
  	Base64Decode(signature_base64, &base64DecodeOutput, &test);
	int res=RSA_verify(NID_sha256, output, strlen(output),base64DecodeOutput, 256, rsa_public_key);
	if (res==1){ 
		printf("\nSIGNATURE VERIFIED!!!(SIGNATURES MATCH)\n\n");
	}
	else if (res==0){
		printf("\nCAUTION!!! SIGNATURE NOT VERIFIED!!!(SIGNATURES DONT MATCH)\n\n");
	}
  }
  else{
    	printf("WRONG NUMBER OF PARAMETERS GIVEN!!!\n");
    	printf("THE PROGRAM WILL EXIT FOR YOUR SAFETY!!!\n");
  }
  printf("Thank you for using our program. :)\n");
}


