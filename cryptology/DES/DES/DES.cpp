#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctime>

typedef struct
{
    const char* plainfile;
    const char* keyfile;
    const char* vifile;
    const char* mode;
    const char* cipherfile;
}s_param;//命令行参数

char init[65] = "\0";
char putin_i[17];
int i = 0;
char temp1[65] = "\0";
char temp2[9] = "\0";


    char regist[65];//移位寄存器二进制
    char ming_key_64[65];//秘钥二进制
    char result1[65] = "\0";//输出二进制
    //初始化向量二进制

    char putin_k[17];//秘钥十六进制

    char mingwen_8[9];//明文二进制
    char miwen_8[9];//密文二进制
    char putin_m[3];//明文十六进制
    char f_result[3] = "\0";//密文十六进制



//密钥
//64位变56位密钥置换表
int pc_1[56] = {
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};
//循环左移表
int left_list[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };
//56位变48位密钥置换表
int pc_2[48] = {
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
};

//明文
//IP置换表
int IP[64] = {
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
};
//r数组拓展置换表
int E[48] = {
    32,1,2,3,4,5,
    4,5,6,7,8,9,
    8,9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1
};
//l数组s盒置换表
int s_box[8][4][16] = {
    14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
    0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
    4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
    15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,

    15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
    3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
    0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
    13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,

    10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
    13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
    13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
    1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,

    7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
    13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
    10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
    3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,

    2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
    14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
    4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
    11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,

    12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
    10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
    9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
    4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,

    4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
    13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
    1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
    6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,

    13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
    1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
    7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
    2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
};
//P盒置换
int p[32] = { 16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25 };
//IP逆置换表
int IP_[64] = {
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
};

//数组元素倒置1234→4321,arr为初始数组，start为数组的初始位置,end为数组的末尾位置
void Reverse(char* arr, int start, int end) {
    for (; start < end; start++, end--) {
        int s = arr[end];
        arr[end] = arr[start];
        arr[start] = s;
    }
}
//arr初始数组,n数组长度,k左移位数  1234567
void LeftShift(char* arr, int n, int k) {
    k = k % n;
    Reverse(arr, 0, k - 1);//将前面k位逆置1234->4321
    Reverse(arr, k, n - 1);//将后面几位逆置 567->765
    Reverse(arr, 0, n - 1);//整个数组逆置4321765->5671234
}
//置换表，a为初始数组,change置换表,result结果数组,len想要置换的长度
//如，change[1]=14，就是将a的第二个数和第十四个数置换，第十四个数实际上是a[13]
void change_table(char* a, int* change, char* result, int len) {
    int i;
    for (i = 0; i < len; i++) {
        result[i] = a[change[i] - 1];
    }
}
//合并数组，密钥合并andL1 R1合并
void merge(char* dest, char* src1, char* src2)
{
    while (*src1) *dest++ = *src1++;
    while (*src2) *dest++ = *src2++;
}
//子密钥生成函数，key为初始64位密钥,key_48为子密钥生成后的48位密钥
void get_16_key(char* key_64, char key_48[][49]) {
    char key_56[57] = "\0";//第一次置换后保存的56位密钥
    char c[17][28];
    char d[17][28];//需要用到c0-c16，每个28位

    //为c和d申请空间
    memset(c, 0, sizeof(c));
    memset(d, 0, sizeof(d));
    change_table(key_64, pc_1, key_56, 56);//第一次置换，64位密钥

    //c0d0初始化
    for (int i = 0; i < 56; i++) {
        if (i < 28) {
            c[0][i] = key_56[i];//前面28位密钥赋值给c0
            //printf("%c",c[0][i]);
        }
        else {
            d[0][i - 28] = key_56[i];//前面28位密钥赋值给c0
           // printf("%c",d[0][i-28]);
        }
    }
    //生成后面的16个子密钥
    //printf("16个子密钥为: \n");
    for (int i = 1, j = 0; i < 17; i++, j++) {
        for (int s = 0; s < 28; s++) {
            c[i][s] = c[i - 1][s];
            d[i][s] = d[i - 1][s];
        }
        LeftShift(d[i], sizeof(d[i]), left_list[j]);
        LeftShift(c[i], sizeof(c[i]), left_list[j]);
        //每次左移完成后，将c和d拼接起来并进行第二次置换为48位子密钥
        memset(key_56, 0, strlen(key_56));
        for (int k = 0; k < 56; k++) {
            if (k < 28)
                key_56[k] = c[i][k];
            else
                key_56[k] = d[i][k - 28];
        }
        change_table(key_56, pc_2, key_48[i - 1], 48);//得到最终的子密钥

        //printf("k%d=", i);
        //puts(key_48[i - 1]);
    }
}
//二进制转十六进制
char* to16(char* result0, static char* final_result, int n) {
    int i;
    int result[65] = { 0 };
    for (i = 0; i < 4*n; i++)
    {
        result[i] = result0[i] - '0';
    }
    for (i = 0; i < n; i++)
    {
        int sum;
        sum = result[4 * i] * 8 + result[4 * i + 1] * 4 + result[4 * i + 2] * 2 + result[4 * i + 3] * 1;
        switch (sum)
        {
            case 1:
                final_result[i] = '1';
                break;
            case 2:
                final_result[i] = '2';
                break;
            case 3:
                final_result[i] = '3';
                break;
            case 4:
                final_result[i] = '4';
                break;
            case 5:
                final_result[i] = '5';
                break;
            case 6:
                final_result[i] = '6';
                break;
            case 7:
                final_result[i] = '7';
                break;
            case 8:
                final_result[i] = '8';
                break;
            case 9:
                final_result[i] = '9';
                break;
            case 10:
                final_result[i] = 'A';
                break;
            case 11:
                final_result[i] = 'B';
                break;
            case 12:
                final_result[i] = 'C';
                break;
            case 13:
                final_result[i] = 'D';
                break;
            case 14:
                final_result[i] = 'E';
                break;
            case 15:
                final_result[i] = 'F';
                break;
            case 0:
                final_result[i] = '0';
                break;
        default:
            break;
        }
    }
    return final_result;
}
//十六进制转二进制
void to2(char* putin_m, static char* mingwen_64, int n) {
    int i;
    for (i = 0; i < n; i++)
    {
        switch (putin_m[i])
        {
        case '0':
            mingwen_64[4 * i] = '0';
            mingwen_64[4 * i + 1] = '0';
            mingwen_64[4 * i + 2] = '0';
            mingwen_64[4 * i + 3] = '0';
            break;
        case '1':
            mingwen_64[4 * i] = '0';
            mingwen_64[4 * i+1] = '0';
            mingwen_64[4 * i+2] = '0';
            mingwen_64[4 * i+3] = '1';
            break;
        case '2':
            mingwen_64[4 * i] = '0';
            mingwen_64[4 * i + 1] = '0';
            mingwen_64[4 * i + 2] = '1';
            mingwen_64[4 * i + 3] = '0';
            break;
        case '3':
            mingwen_64[4 * i] = '0';
            mingwen_64[4 * i + 1] = '0';
            mingwen_64[4 * i + 2] = '1';
            mingwen_64[4 * i + 3] = '1';
            break;
        case '4':
            mingwen_64[4 * i] = '0';
            mingwen_64[4 * i + 1] = '1';
            mingwen_64[4 * i + 2] = '0';
            mingwen_64[4 * i + 3] = '0';
            break;
        case '5':
            mingwen_64[4 * i] = '0';
            mingwen_64[4 * i + 1] = '1';
            mingwen_64[4 * i + 2] = '0';
            mingwen_64[4 * i + 3] = '1';
            break;
        case '6':
            mingwen_64[4 * i] = '0';
            mingwen_64[4 * i + 1] = '1';
            mingwen_64[4 * i + 2] = '1';
            mingwen_64[4 * i + 3] = '0';
            break;
        case '7':
            mingwen_64[4 * i] = '0';
            mingwen_64[4 * i + 1] = '1';
            mingwen_64[4 * i + 2] = '1';
            mingwen_64[4 * i + 3] = '1';
            break;
        case '8':
            mingwen_64[4 * i] = '1';
            mingwen_64[4 * i + 1] = '0';
            mingwen_64[4 * i + 2] = '0';
            mingwen_64[4 * i + 3] = '0';
            break;
        case '9':
            mingwen_64[4 * i] = '1';
            mingwen_64[4 * i + 1] = '0';
            mingwen_64[4 * i + 2] = '0';
            mingwen_64[4 * i + 3] = '1';
            break;
        case 'A':
            mingwen_64[4 * i] = '1';
            mingwen_64[4 * i + 1] = '0';
            mingwen_64[4 * i + 2] = '1';
            mingwen_64[4 * i + 3] = '0';
            break;
        case 'B':
            mingwen_64[4 * i] = '1';
            mingwen_64[4 * i + 1] = '0';
            mingwen_64[4 * i + 2] = '1';
            mingwen_64[4 * i + 3] = '1';
            break;
        case 'C':
            mingwen_64[4 * i] = '1';
            mingwen_64[4 * i + 1] = '1';
            mingwen_64[4 * i + 2] = '0';
            mingwen_64[4 * i + 3] = '0';
            break;
        case 'D':
            mingwen_64[4 * i] = '1';
            mingwen_64[4 * i + 1] = '1';
            mingwen_64[4 * i + 2] = '0';
            mingwen_64[4 * i + 3] = '1';
            break;
        case 'E':
            mingwen_64[4 * i] = '1';
            mingwen_64[4 * i + 1] = '1';
            mingwen_64[4 * i + 2] = '1';
            mingwen_64[4 * i + 3] = '0';
            break;
        case 'F':
            mingwen_64[4 * i] = '1';
            mingwen_64[4 * i + 1] = '1';
            mingwen_64[4 * i + 2] = '1';
            mingwen_64[4 * i + 3] = '1';
            break;
        default:
            break;
        }
    }
    //return mingwen_64;
}

//加密算法
void des(char* mingwen_64, char* key_64, char* result, int type) {
    int i, j, k;
    char key_48[16][49];//16个子密钥48位
    char mingwen_IP[65] = "\0";//IP 置换后的64位明文
    char r_48[49] = "\0";//拓展置换后
    char l[17][33];
    char r[17][33];//左半和右半待加密分组
    char bit6[8][6];//s盒置换中用到的8个6位的块
    char r_32[33] = "\0";//p盒置换后的32位

    memset(key_48, 0, sizeof(key_48));
    memset(l, 0, sizeof(l));
    memset(r, 0, sizeof(r));
    memset(bit6, 0, sizeof(bit6));

    get_16_key(key_64, key_48);//获取16个子密钥保存在key_48中
    change_table(mingwen_64, IP, mingwen_IP, 64);//对明文进行IP置换

    //初始化L0R0
    for (i = 0; i < 64; i++) {
        if (i < 32) {
            l[0][i] = mingwen_IP[i];
        }
        else {
            r[0][i - 32] = mingwen_IP[i];
        }
    }

    //16次递推运算
    //printf("敖瑞梅的学号是：2022141530034\n");
    for (i = 1; i < 17; i++) {      //Rn=L(n-1)异或P( S ( ( E ( R(n-1) ) 异或 Kn ) ) )
        //获取ln
        for (j = 0; j < 32; j++) {
            l[i][j] = r[i - 1][j];
        }
        //获取rn
        //拓展置换，将r从32位拓展到48位
        change_table(r[i - 1], E, r_48, 48);

        //与k子密钥进行异或
        int ch;
        if (type == 1) {    //加密
            for (j = 0; j < 48; j++) {
                ch = r_48[j] ^ key_48[i - 1][j];
                r_48[j] = ch + '0';
            }
        }
        else {
            for (j = 0; j < 48; j++) {
                ch = r_48[j] ^ key_48[16 - i][j];
                r_48[j] = ch + '0';
            }
        }

        //s盒转换为32位
        int a = 0;
        int b = 0;//控制s盒置换后的位置
        
        for (j = 0; j < 8; j++) {    //48位数据分为8个6位的块,0-7
            for (k = 0; k < 6; k++) {
                bit6[j][k] = r_48[a];
                a++;
            }
            int x, y, re;//x行数 y列数 re结果
            x = (bit6[j][0] - '0') * 2 + (bit6[j][5] - '0');//取出这一块当中第一位和第六位形成十进制数x作为行数
            y = (bit6[j][1] - '0') * 8 + (bit6[j][2] - '0') * 4 + (bit6[j][3] - '0') * 2 + (bit6[j][4] - '0');//取出中间的4位形成十进制数作为列数
            //每一块都有一个对应的s盒
            re = s_box[j][x][y];//去这一块对应的s盒中的x行y列找到结果
            //结果转成二进制
            char str[4] = {'0','0','0','0'};
            int q = 0;//余数
            int c = 3;
            while (re != 0) {
                q = re % 2;
                str[c] = q + 48;
                c--;
                re = re / 2;
            }
            for (int d = 0; d < 4; d++) {
                r[i][b] = str[d];
                b++;
            }
            /*char str[5] = { '0','0','0','0','\0'};
            memset(str, '0', sizeof(str));
            int q = 0;
            int c = 3;
            while (re != 0) {
                q = re % 2;
                str[2] = q;
                c--;
                re = re / 2;
            }
            for (int d = 0; d < 4; d++) {
                r[i][b] = str[d];
                b++;
            }
            printf("str=");
            puts(str);
            printf("\n");*/
        }
        //p盒置换后与l数组进行异或
        change_table(r[i], p, r_32, 32);
        for (j = 0; j < 32; j++) {
            r[i][j] = (l[i - 1][j] ^ r_32[j]) + '0';
        }
      /* if (i == 2022141530034 % 16) {
        printf("N=%d\n", i);
        printf("L%d=", i);
        puts(l[i]);
        printf("R%d=", i);
        puts(r[i]);
        }*/
       
    }
    //由r16l16和一次IP逆置换获得最终的密文
    for (i = 0; i < 64; i++) {
        if (i < 32) {
            mingwen_64[i] = r[16][i];
        }
        else {
            mingwen_64[i] = l[16][i - 32];
        }
    }
    change_table(mingwen_64, IP_, result, 64);//IP逆置换最后的密文
}


//ECB算法
int ECB(const char* plainfile, const char* keyfile, const char* cipherfile)
{
    char putin_m[17];
    char putin_k[17];

    char f_result[17] = "\0";
    char mingwen_64[65];
    char result1[65] = "\0";//由明文加密得到的密文
    char ming_key_64[65];

    FILE* pFile2 = fopen(cipherfile, "a");//打开密文文件
    FILE* pFile1 = fopen(plainfile, "r");//打开明文文件

    FILE* pFile0 = fopen(keyfile, "r");//打开秘钥文件
    fread(putin_k, sizeof(char), 16, pFile0);
    fclose(pFile0);
    to2(putin_k, ming_key_64,16);

    int flag = fread(putin_m, sizeof(char), 16, pFile1);
    while (flag)
    {
        to2(putin_m, mingwen_64,16);
        des(mingwen_64, ming_key_64, result1, 1);
        to16(result1, f_result, 16);
        fwrite(f_result, sizeof(char), 16, pFile2);
        flag = fread(putin_m, sizeof(char), 16, pFile1);
    }
    fclose(pFile1);
    fclose(pFile2);
    return 0;
}

//按位异或函数
void myXOR(char* In1, char* In2, int n, char* Out)
{
    int i = 0;
    for (i = 0; i < n; i++)
        *(In1 + i) != *(In2 + i) ? *(Out + i) = '1' : *(Out + i) = '0';
}

//CBC
int CBC(const char* plainfile, const char* keyfile, const char* cipherfile, const char* vifile)
{
    char putin_m[17];
    char putin_k[17];

    char f_result[17] = "\0";
    char mingwen_64[65];
    char result1[65] = "\0";//由明文加密得到的密文
    char ming_key_64[65];

    FILE* pFile2 = fopen(cipherfile, "a");//打开密文文件
    FILE* pFile1 = fopen(plainfile, "r");//打开明文文件

    FILE* pFile3 = fopen(keyfile, "r");//打开秘钥文件
    fread(putin_k, sizeof(char), 16, pFile3);
    fclose(pFile3);
    to2(putin_k, ming_key_64, 16);

    FILE* pFile4 = fopen(vifile, "r");//打开初始化向量文件
    fread(putin_i, sizeof(char), 16, pFile4);
    fclose(pFile4);
    to2(putin_i, init, 16);

    int flag = fread(putin_m, sizeof(char), 16, pFile1);
    to2(putin_m, mingwen_64, 16);
    strcpy(temp1, mingwen_64);
    myXOR(temp1, init, 64, mingwen_64);

    while (flag)
    {
        //to2(putin_m, mingwen_64);
        des(mingwen_64, ming_key_64, result1, 1);
        to16(result1, f_result, 16);
        fwrite(f_result, sizeof(char), 16, pFile2);
        flag = fread(putin_m, sizeof(char), 16, pFile1);
        to2(putin_m, mingwen_64, 16);
        strcpy(temp1, mingwen_64);
        myXOR(temp1, result1, 64, mingwen_64);
    }
    fclose(pFile1);
    fclose(pFile2);
    return 0;
}

void move(char* reg, char* cipher, int t)
{
    int j, i = 0;
    while (i < strlen(reg) - t)
    {
        reg[i] = reg[i + t];
        i++;
    }
    for (j = 0; j < t; j++)
        reg[i + j] = cipher[j];
}

//CFB
int CFB(const char* plainfile, const char* keyfile, const char* cipherfile, const char* vifile)
{


    FILE* pFile2 = fopen(cipherfile, "a");//打开密文文件
    FILE* pFile1 = fopen(plainfile, "r");//打开明文文件

    FILE* pFile3 = fopen(keyfile, "r");//打开秘钥文件
    fread(putin_k, sizeof(char), 16, pFile3);
    fclose(pFile3);
    to2(putin_k, ming_key_64, 16);//获得二进制

    FILE* pFile4 = fopen(vifile, "r");//打开初始化向量文件
    fread(putin_i, sizeof(char), 16, pFile4);
    fclose(pFile4);
    to2(putin_i, init, 16);//获得二进制

    int flag = fread(putin_m, sizeof(char), 2, pFile1);
    to2(putin_m, mingwen_8, 2);
    strcpy(regist, init);

    while (flag)
    {
        //to2(putin_m, mingwen_64);
        des(regist, ming_key_64, result1, 1);

        strncpy(temp2, result1, 8);//选择最左边的8位
        myXOR(temp2, mingwen_8, 8, miwen_8);
        to16(miwen_8, f_result, 2);
        fwrite(f_result, sizeof(char), 2, pFile2);
        move(init, miwen_8, 8);
        flag = fread(putin_m, sizeof(char), 2, pFile1);
        to2(putin_m, mingwen_8, 2);
        strcpy(regist, init);
    }
    fclose(pFile1);
    fclose(pFile2);
    return 0;
}

//OFB
int OFB(const char* plainfile, const char* keyfile, const char* cipherfile, const char* vifile)
{


    FILE* pFile2 = fopen(cipherfile, "a");//打开密文文件
    FILE* pFile1 = fopen(plainfile, "r");//打开明文文件

    FILE* pFile3 = fopen(keyfile, "r");//打开秘钥文件
    fread(putin_k, sizeof(char), 16, pFile3);
    fclose(pFile3);
    to2(putin_k, ming_key_64, 16);//获得二进制

    FILE* pFile4 = fopen(vifile, "r");//打开初始化向量文件
    fread(putin_i, sizeof(char), 16, pFile4);
    fclose(pFile4);
    to2(putin_i, init, 16);//获得二进制

    int flag = fread(putin_m, sizeof(char), 2, pFile1);
    to2(putin_m, mingwen_8, 2);
    strcpy(regist, init);

    while (flag)
    {
        //to2(putin_m, mingwen_64);
        des(regist, ming_key_64, result1, 1);

        strncpy(temp2, result1, 8);//选择最左边的8位
        myXOR(temp2, mingwen_8, 8, miwen_8);
        to16(miwen_8, f_result, 2);
        fwrite(f_result, sizeof(char), 2, pFile2);
        move(init, temp2, 8);
        flag = fread(putin_m, sizeof(char), 2, pFile1);
        to2(putin_m, mingwen_8, 2);
        strcpy(regist, init);
    }
    fclose(pFile1);
    fclose(pFile2);
    return 0;
}

//计时函数
void test()
{
    s_param param;
    int i = 0;
    param.plainfile = "plainfile2.txt";
    param.cipherfile = "cipherfile.txt";
    param.keyfile = "keyfile.txt";
    param.vifile = "vifile.txt";
    param.mode = "OFB";
    clock_t start, end;

    start = clock();
    for (; i < 20; i++)
    {
        ECB(param.plainfile, param.keyfile, param.cipherfile);
       // end = clock();
        //printf("CBC模式花的时间：%d  ms\n", (int)(end - start));
    }
    end = clock();
    printf("OFB模式花的时间：%d  ms", (int)(end - start));
    getchar();
}



int main(int argc, char* argv[]) {
   // char putin_m[17];
   // char putin_k[17];
   // char putin_c[17];
   // char f_result[17]="\0";
   // char mingwen_64[65];
   // char result1[65] = "\0";//由明文加密得到的密文
   // char ming_key_64[65];

   // char miwen_64[65];//密文
   // char mi_key_64[65];//64位解密密钥
   // char result2[65] = "\0";//由密文解密得到的明文

   // printf("请输入要加密的明文：");
   // gets_s(putin_m);
   // to2(putin_m, mingwen_64,16);

   // printf("请输入加密密钥：");
   // gets_s(putin_k);
   //to2(putin_k, ming_key_64,16);
   // //加密
   // printf("加密过程：\n");
   // des(mingwen_64, ming_key_64, result1, 1);//1代表加密
   // printf("加密后的密文为：\n");
   // printf("%s\n",result1);
   // to16(result1, f_result,16);
   // printf("%s\n", f_result);

   // printf("请输入要解密的密文：");
   // gets_s(putin_c);
   // to2(putin_c, miwen_64,16);

   // printf("请输入解密密钥：");
   // gets_s(putin_k);
   // to2(putin_k, mi_key_64,16);
   // //解密
   // printf("解密过程：\n");
   // des(miwen_64, mi_key_64, result2, 2);//2代表解密
   // printf("解密后的明文为：\n");
   // puts(result2);
   // to16(result2, f_result,16);
   // printf("%s\n", f_result);
    s_param param;
    int i = 1;
    param.plainfile = "plainfile.txt";
    param.cipherfile = "cipherfile.txt";
    param.keyfile = "keyfile.txt";
    param.vifile = "vifile.txt";
    param.mode = "ECB";//如果没有输入参数默认为ECB

    while (i < argc)
    {
        if (!strcmp(argv[i], "-p"))
            param.plainfile = argv[i + 1];
        else if (!strcmp(argv[i], "-k"))
            param.keyfile = argv[i + 1];
        else if (!strcmp(argv[i], "-m"))
            param.mode = argv[i + 1];
        else if (!strcmp(argv[i], "-c"))
            param.cipherfile = argv[i + 1];
        else if (!strcmp(argv[i], "-v"))
            param.vifile = argv[i + 1];
        i += 2;
    }
    if (!strcmp(param.mode, "ECB"))
        ECB(param.plainfile, param.keyfile, param.cipherfile);
    else if (!strcmp(param.mode, "CBC"))
        CBC(param.plainfile, param.keyfile, param.cipherfile, param.vifile);
    else if (!strcmp(param.mode, "CFB"))
        CFB(param.plainfile, param.keyfile, param.cipherfile, param.vifile);
    else if (!strcmp(param.mode, "OFB"))
        OFB(param.plainfile, param.keyfile, param.cipherfile, param.vifile);
    else
        printf("Wrong mode!Please try again!");

    printf("DONE!");
  //  test();
    return 0;
}


