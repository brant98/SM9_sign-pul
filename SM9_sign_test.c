#include<time.h>
#include"sm9_standard.h"
int SM9_sign_test()
{
    //the master private key
    unsigned char dA[32] = { 0x00, 0x01, 0x30, 0xE7, 0x84, 0x59, 0xD7, 0x85, 0x45, 0xCB, 0x54, 0xC5, 0x87, 0xE0, 0x2C, 0xF4,
                           0x80, 0xCE, 0x0B, 0x66, 0x34, 0x0F, 0x31, 0x9F, 0x34, 0x8A, 0x1D, 0x5B, 0x1F, 0x2D, 0xC5, 0xF4 };
    unsigned char rand[32] = { 0x00, 0x03, 0x3C, 0x86, 0x16, 0xB0, 0x67, 0x04, 0x81, 0x32, 0x03, 0xDF, 0xD0, 0x09, 0x65, 0x02,
                              0x2E, 0xD1, 0x59, 0x75, 0xC6, 0x62, 0x33, 0x7A, 0xED, 0x64, 0x88, 0x35, 0xDC, 0x4B, 0x1C, 0xBE };

    unsigned char h[32], S[64];    // 签名存放
    unsigned char Ppub[128], dSA[64];

    unsigned char hid[] = { 0x01 };

    unsigned char* IDA = "PuLang";
    unsigned char* message = "Be there or be square!";//待签名消息
    int mlen = strlen(message), tmp; //待签名消息长度
    big ks;
    clock_t start, finish;//计算运行时间用
    start = clock();


    tmp = SM9_init(); //初始化椭圆曲线
    if (tmp != 0)
        return tmp;
    ks = mirvar(0);
    bytes_to_big(32, dA, ks);
   
    // printf("\n*********************** SM9 key Generation ***************************\n");
    tmp = SM9_generatesignkey(hid, IDA, strlen(IDA), ks, Ppub, dSA);
    if (tmp != 0)
        return tmp;

        // printf("\n********************** SM9 signature algorithm***************************\n");
        tmp = SM9_sign(hid, IDA, message, mlen, rand, dSA, Ppub, h, S);
        if (tmp != 0)
            return tmp;

  
        //printf("\n******************* SM9 verification algorithm *************************\n");
        tmp = SM9_signVerify(h, S, hid, IDA, message, mlen, Ppub);
        if (tmp != 0)
            return tmp;

 


   
    return 0;
}
