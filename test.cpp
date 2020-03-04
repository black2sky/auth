#include <iostream>
#include <unistd.h>
#include "tocken.h"
#include <stdio.h>
#include <cstdlib>
#include <ctime>
#include <sys/time.h>

int main()
{
	int count = 0;
	int result;
	//result = authentication("ff8081816e4a41d7016e4a4efdd40004", "DSAI-2508-ADF_");//zhengshi
	//result = authentication("ff8081816e4983a3016e49a9d7520000", "DSAI-2508-DSM-ADAS");//ce shi
	result = authentication("ff8081817056dd510170575734c30000", "DSM_V1.0", "/dev/ttyUSB2");
	printf("%d. auth result: %d\n", count, result);

	while(1)
	{
		count++;
		usleep(10000000);
		result = authentication("ff8081817056dd510170575734c30000", "DSM_V1.0");
		printf("%d. auth result: %d\n", count, result);
	}


//	srand((int)time(0))	;
//	long long checkCode = rand()%1000;
//
//	while(1)
//	{
//		usleep(1000000);
//
//		checkCode++;
//	    struct timeval tv;
//		gettimeofday(&tv,NULL);
//
//		long long sec = tv.tv_sec;
//		char strSec[16] = {0};
//		char strCheckCode[16] = {0};
//		sprintf(strSec,"%lld",sec);
//		sprintf(strCheckCode,"%lld",checkCode);
//
//		int len = strlen(strSec) + strlen(strCheckCode);
//		char *raw = (char *) malloc(len);
//		strcpy(raw, strSec);
//		strcat(raw, strCheckCode);
//		printf("raw: %s\nstrSec: %s, checkCode: %s\n", raw, strSec, strCheckCode);
//
//		char *raw_buf = NULL;
//		char *after_padding_buf = NULL;
//		int padding_size = 0;
//		char *encrypt_buf = NULL;
//		char decrypt_buf[128] = {0};
//
//		raw_buf = (char *)malloc(len);
//		memcpy(raw_buf,raw,len);
//
//		after_padding_buf = padding_buf(raw_buf,len,&padding_size);
//		printf("after_padding_buf: %s, size: %d\n", after_padding_buf, padding_size);
//		encrypt_buf = (char *)malloc(padding_size);
//		encrpyt_buf(after_padding_buf, encrypt_buf, padding_size);
//
//
//
//	    FILE *fp = NULL;
//	    char buff[255];
//	    fp = fopen(MYFILE, "w+");
//	    if(fp != NULL)
//	    {
//	    	char buff3[256] = {0};
//	    	fgets(buff3, 255, (FILE*)fp);
//	    	printf("buff3: %s\n", buff3);
//	    	fprintf_buff(encrypt_buf, padding_size, fp);
//	    	fclose(fp);
//	    }
//
//		printf("encrypt_buf: %s\n", encrypt_buf);
//
//	    char buff2[256] = {0};
//	    fp = fopen(MYFILE, "r");
//
//	    if(fp != NULL)
//	    {
//	    	fgets(buff2, 255, (FILE*)fp);
//	    	fclose(fp);
//	    }
//	    unsigned char result[256] = {0};
//	    unsigned int resultLen = 0;
//	    int test2 = hex2str(buff2, result, &resultLen);
//	    printf("encrypt_buf: %s\n", result);
//
//
//		decrpyt_buf((char *)result, decrypt_buf, test2);
//		printf("decrypt_buf: %s\n", decrypt_buf);
//
//		char new_buf[128] = {0};
//		char new_code[16] = {0};
//		strncpy(new_buf, decrypt_buf, 10);
//		strncpy(new_code, decrypt_buf + 10, strlen(decrypt_buf) - 10);
//		long long t;
//		long long code;
//		sscanf(new_buf, "%lld", &t);
//		sscanf(new_code, "%lld", &code);
//		printf("new_buf: %s, %lld, %lld\n", new_buf, t, code);
//		if(strcmp(decrypt_buf, after_padding_buf) != 0)
//			break;
//		free(raw_buf);
//		free(after_padding_buf);
//		free(encrypt_buf);
//		//free(decrypt_buf);
//
//	}

	return 0;
}
