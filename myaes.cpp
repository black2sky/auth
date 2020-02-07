#include "myaes.h"

char* MYKEY	= (char*)"55aad5705d5c46f4c8af8cbedc72b012";
char* MYIV = (char*)"667b0c711060265e8686def45212a85c";

void str2hex(char *str, unsigned char * out)
{
    int str_len = strlen(str);
    int i = 0;
    assert((str_len%2) == 0);
    for (i =0;i < str_len; i = i+2 )
    {
        sscanf(str+i,"%2hhx",&out[i/2]);
    }
    return;
}

int hex2str(char *str, unsigned char *out, unsigned int *outlen)
{
    char *p = str;
    char high = 0, low = 0;
    int tmplen = strlen(p), cnt = 0;
    tmplen = strlen(p);
    while(cnt < (tmplen / 2))
    {
        high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
		low = (*(++ p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p) - 48 - 7 : *(p) - 48;
        out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
        p ++;
        cnt ++;
    }
    if(tmplen % 2 != 0) out[cnt] = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;

    if(outlen != NULL) *outlen = tmplen / 2 + tmplen % 2;
    return tmplen / 2 + tmplen % 2;
}

void fprintf_buff(char *buff,int size, FILE *fp)
{
    int i = 0;
    for (i=0;i<size;i ++ )
    {
        fprintf(fp, "%02X", (unsigned char)buff[i] );
    }
}

char *padding_buf(char *buf,int size, int *final_size)
{
    char *ret = NULL;
    int pidding_size = AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE);
    int i;
    *final_size = size + pidding_size;
    ret = (char *)malloc(size + pidding_size);
    memcpy( ret, buf, size);
    if (pidding_size!=0)
    {
        for (i =size;i < (size+pidding_size); i++ )
        {
            ret[i] = 0;
        }
    }
    return ret;
}

void encrpyt_buf(char *raw_buf, char *encrpy_buf, int len)
{
    AES_KEY aes;
    unsigned char myKey[32] = {0};
    unsigned char myIv[32] = {0};
    str2hex(MYKEY, myKey);
    str2hex(MYIV, myIv);
    AES_set_encrypt_key(myKey,128,&aes);
    AES_cbc_encrypt((unsigned char*)raw_buf, (unsigned char*)encrpy_buf, len,&aes, myIv, AES_ENCRYPT);
}

void decrpyt_buf(char *raw_buf, char *encrpy_buf, int len)
{
    AES_KEY aes;
    unsigned char myKey[32] = {0};
    unsigned char myIv[32] = {0};
    str2hex(MYKEY, myKey);
    str2hex(MYIV, myIv);
    AES_set_decrypt_key(myKey,128,&aes);
    AES_cbc_encrypt((unsigned char*)raw_buf, (unsigned char*)encrpy_buf,len, &aes, myIv, AES_DECRYPT);
}
