#ifndef __MYAES_H__
#define __MYAES_H__

#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

void str2hex(char *str, unsigned char * out);
int hex2str(char *str, unsigned char *out, unsigned int *outlen);
void fprintf_buff(char *buff,int size, FILE *fp);
char *padding_buf(char *buf,int size, int *final_size);
void encrpyt_buf(char *raw_buf, char *encrpy_buf, int len);
void decrpyt_buf(char *raw_buf, char *encrpy_buf, int len);

#endif
