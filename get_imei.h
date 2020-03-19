#ifndef _GET_IMEI_H_
#define _GET_IMEI_H_
#define LOG(format,...) printf("[***** DSAI_AUTH *****]" format "\n",  ##__VA_ARGS__)
void setImeiDevPath(const char* ImeiDevPath);
const char* get_imei(int type);

#endif
