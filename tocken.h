#ifndef _TOCKEN_H_
#define _TOCKEN_H_
#include <iostream>

// 参数(1.key： 用户申请id+key   2.algVersion： 算法版本   3.imeiDevPath: imei读取路径缺, 省参数为空),
// 函数返回(0为成功)
int authentication(std::string key, std::string algVersion, std::string imeiDevPath = "");


#endif
