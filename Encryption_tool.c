#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>
#include <sys/stat.h>

/*@author Paraschidis Panagiotis 3164*/

#include <sys/types.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, int,unsigned char *, unsigned char *, int);
unsigned char* encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
unsigned char* decrypt(unsigned char *, int, unsigned char *, unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *,int);



/* TODO Declare your function prototypes here... */
EVP_CIPHER_CTX *eContext;
EVP_CIPHER_CTX *deContext;
int ciphertext_len=0;
int decryptedtext_len=0;

size_t maclen;
/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password,int passLength, unsigned char *key, unsigned char *iv,
    int bit_mode)
{
	
	
	if(bit_mode==128){
		EVP_BytesToKey(EVP_aes_128_ecb(), EVP_sha1(), NULL, password, passLength, 1, key, NULL);
		EVP_DecryptInit_ex(deContext,EVP_aes_128_ecb(),NULL,key,NULL);
        EVP_EncryptInit_ex(eContext, EVP_aes_128_ecb(),NULL,key,NULL);  
	}else if(bit_mode==256){
		EVP_BytesToKey(EVP_aes_256_ecb(), EVP_sha1(), NULL, password, passLength, 1, key, NULL);
		EVP_DecryptInit_ex(deContext,EVP_aes_256_ecb(),NULL,key,NULL);
        EVP_EncryptInit_ex(eContext, EVP_aes_256_ecb(),NULL,key,NULL);
	}else{
		fprintf(stderr, "Uknown bit_mode\n");
	}
	
         
}


/*
 * Encrypts the data
 */
unsigned char*
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{
	//size_t block=0;
	int msgLen=0;
	int cip_len=plaintext_len+BLOCK_SIZE;
	ciphertext=malloc(cip_len);
	if(ciphertext==NULL){
		fprintf(stderr,"Malloc failed for ciphertext in encrypt\n" );
		exit(-1);
	}

	EVP_EncryptUpdate(eContext, ciphertext,&msgLen, plaintext,plaintext_len);
	ciphertext_len=msgLen;
	EVP_EncryptFinal_ex(eContext, ciphertext+msgLen,&msgLen);

	plaintext_len=cip_len+msgLen;

	ciphertext_len+=msgLen;
	return ciphertext;
	

}


/*
 * Decrypts the data and returns the plaintext size
 */
unsigned char *
decrypt(unsigned char *ciphertext, int ciphertext_leng, unsigned char *key,
    unsigned char *iv, int bit_mode)
{
	int plaintext_len;
	
	int msgLen;

	unsigned char* plaintext=malloc(ciphertext_leng+BLOCK_SIZE);

	if(plaintext==NULL){
		fprintf(stderr,"Malloc failed for plaintext in decrypt\n" );
		exit(-1);
	}
	
	
	EVP_DecryptUpdate(deContext,plaintext,&msgLen, ciphertext,ciphertext_leng);

	plaintext_len=msgLen;

	EVP_DecryptFinal_ex(deContext,plaintext+msgLen,&msgLen);
	plaintext_len+=msgLen;
	
	
	decryptedtext_len=plaintext_len;
	

	return plaintext;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{
	
	CMAC_CTX *cmacContext = CMAC_CTX_new();
	if(bit_mode==128){
		CMAC_Init(cmacContext, key, 16, EVP_aes_128_ecb(), NULL);	
  	}else if(bit_mode==256){
  		CMAC_Init(cmacContext, key, 32, EVP_aes_256_ecb(), NULL);	
  	
  	}else{
  		fprintf(stderr, "Uknown bit_mode\n");
  		exit(-1);
  	}
  	CMAC_Update(cmacContext, data, data_len);
    CMAC_Final(cmacContext, cmac, &maclen);
    CMAC_CTX_free(cmacContext);
  	 
}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2,int bit_mode)
{
	int verify;

	verify = 0;
	int i;
	if(bit_mode==128){
		for(i=0;i<16;i++){
			if(cmac1[i]!=cmac2[i]){
				verify=-1;
			}
	}
		
	}else if(bit_mode==256){
		for(i=0;i<32;i++){
			if(cmac1[i]!=cmac2[i]){
				verify=-1;
			}
	}
	
	}else{
  		fprintf(stderr, "Uknown bit_mode\n");
  		exit(-1);
	}
	return verify;
}



/* TODO Develop your functions here... */



/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */

int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;



	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 0 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 2 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 3 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);

	
	unsigned char *plaintext=NULL;//input file
	unsigned char *ciphertext=NULL;//out file

	
	
	eContext=EVP_CIPHER_CTX_new();
	deContext=EVP_CIPHER_CTX_new();
	int x=0;
	
	FILE *fout;
	FILE *f;

 	int passLeng=strlen((const char *)password);
 	if(bit_mode==128){
 		
 		unsigned char key[16];
 		keygen(password,passLeng,key,NULL,bit_mode);
 		if(op_mode==0){
 			fout=fopen(output_file,"wb");
 			f=fopen(input_file,"r");
		 	int fd=fileno(f);
			struct stat buf;
			fstat(fd, &buf);
			int size = buf.st_size;
			plaintext=(unsigned char*)malloc(size);
	 		
	 		x=fread(plaintext,1,size,f);
	 	

			ciphertext=encrypt(plaintext,size,key,NULL,ciphertext,bit_mode);
	
			

			fwrite(ciphertext,1,ciphertext_len,fout);
			fclose(f);
			fclose(fout);

		}
		else if(op_mode==1){
			fout=fopen(output_file,"w");
			f=fopen(input_file,"rb");
			int fd=fileno(f);
			struct stat buf;
			fstat(fd, &buf);
			int size = buf.st_size;

			ciphertext=(unsigned char*)malloc(size);
			
			x=fread(ciphertext,1,size,f);
	
			plaintext=decrypt(ciphertext,size,key,NULL,bit_mode);
	
			fwrite(plaintext,1,decryptedtext_len,fout);
			fclose(fout);
			fclose(f);
			
		}else if(op_mode==2){
			f=fopen(input_file,"r");
			int fd=fileno(f);
			struct stat buf;
			fstat(fd, &buf);
			int size = buf.st_size;
			unsigned char mac[16];
			plaintext=(unsigned char*)malloc(size);
	 		
	 		x=fread(plaintext,1,size,f);

	 		ciphertext=encrypt(plaintext,size,key,NULL,ciphertext,bit_mode);
	 		fout=fopen(output_file,"wb");
	 		fwrite(ciphertext,1,ciphertext_len,fout);
	 		fclose(fout);
	 			
	 		unsigned char *temp=decrypt(ciphertext,ciphertext_len,key,NULL,bit_mode);
	 		
	 		gen_cmac(temp,ciphertext_len,key,mac,bit_mode);

	 		
	 		fout=fopen(output_file,"ab");
	 		fwrite(mac,1,maclen,fout);
	 		fclose(fout);
	 		fclose(f);

		}else if(op_mode==3){
			f=fopen(input_file,"rb");
			int fd=fileno(f);
			struct stat buf;
			fstat(fd, &buf);
			int size = buf.st_size;

			unsigned char mac[16];
			unsigned char tobe[size];
			unsigned char readymac[16];
			int i=0;
			
			x=fread(tobe,1,size,f);
			for(i=0;i<16;i++){
				readymac[i]=tobe[(size-16)+i];
			}
			int newsize=size-16;

			plaintext=decrypt(tobe,newsize,key,NULL,bit_mode);
			gen_cmac(plaintext,newsize,key,mac,bit_mode);
	 		
	 		int res=verify_cmac(readymac,mac,bit_mode);
	 		if(res==0){
	 			printf("True\n");
	 			fout=fopen(output_file,"w");
				fwrite(plaintext,1,newsize,fout);
				fclose(fout);
	 		}else{
	 			printf("False\n");
	 		}
			
			fclose(f);

		}
	
 	}
 	else if (bit_mode==256){
 		unsigned char key[32];
 		keygen(password,passLeng,key,NULL,bit_mode);
 		if(op_mode==0){
 			fout=fopen(output_file,"wb");
 			f=fopen(input_file,"r");
		 	int fd=fileno(f);
			struct stat buf;
			fstat(fd, &buf);
			int size = buf.st_size;
			plaintext=(unsigned char*)malloc(size);
	 		
	 		x=fread(plaintext,1,size,f);
	 		
			ciphertext=encrypt(plaintext,size,key,NULL,ciphertext,bit_mode);

			

			fwrite(ciphertext,1,ciphertext_len,fout);
			fclose(f);
			fclose(fout);

		}
		else if(op_mode==1){
			fout=fopen(output_file,"w");
			f=fopen(input_file,"rb");
			int fd=fileno(f);
			struct stat buf;
			fstat(fd, &buf);
			int size = buf.st_size;

			ciphertext=(unsigned char*)malloc(size);
			
			x=fread(ciphertext,1,size,f);
			
			
			plaintext=decrypt(ciphertext,size,key,NULL,bit_mode);
			
			fwrite(plaintext,1,decryptedtext_len,fout);
			fclose(fout);
			fclose(f);
			
		}else if(op_mode==2){
			f=fopen(input_file,"r");
			int fd=fileno(f);
			struct stat buf;
			fstat(fd, &buf);
			int size = buf.st_size;
			unsigned char mac[32];
			plaintext=(unsigned char*)malloc(size);
	 		
	 		x=fread(plaintext,1,size,f);

	 		ciphertext=encrypt(plaintext,size,key,NULL,ciphertext,bit_mode);
	 		fout=fopen(output_file,"wb");
	 		fwrite(ciphertext,1,ciphertext_len,fout);
	 		fclose(fout);
	 			
	 		unsigned char *temp=decrypt(ciphertext,ciphertext_len,key,NULL,bit_mode);
	 		
	 		gen_cmac(temp,ciphertext_len,key,mac,bit_mode);

	 		
	 		fout=fopen(output_file,"ab");
	 		fwrite(mac,1,maclen,fout);
	 		fclose(fout);
	 		fclose(f);

		}else if(op_mode==3){
			f=fopen(input_file,"rb");
			int fd=fileno(f);
			struct stat buf;
			fstat(fd, &buf);
			int size = buf.st_size;

			unsigned char mac[16];
			unsigned char tobe[size];
			unsigned char readymac[16];
			int i=0;
			
			x=fread(tobe,1,size,f);
			for(i=0;i<16;i++){
				readymac[i]=tobe[(size-16)+i];
			}
			int newsize=size-16;
			
			plaintext=decrypt(tobe,newsize,key,NULL,bit_mode);
			gen_cmac(plaintext,newsize,key,mac,bit_mode);
	 		
	 		int res=verify_cmac(readymac,mac,bit_mode);
	 		if(res==0){
	 			printf("True\n");
	 			fout=fopen(output_file,"w");
				fwrite(plaintext,1,newsize,fout);
				fclose(fout);
	 		}else{
	 			printf("False\n");
	 		}
			
			fclose(f);

		}
 	}

	




	
 	
 	
 	
//encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
//unsigned char *iv, unsigned char *ciphertext, int bit_mode)


	


	
	/* Initialize the library */


	/* Keygen from password */


	/* Operate on the data according to the mode */
	/* encrypt */

	/* decrypt */

	/* sign */

	/* verify */
		

	/* Clean up */
	EVP_CIPHER_CTX_free(eContext);
	EVP_CIPHER_CTX_free(deContext);
	free(plaintext);
	free(ciphertext);
	free(input_file);
	free(output_file);
	free(password);
	//EVP_CIPHER_CTX_cleanup

	/* END */
	return 0;
}
