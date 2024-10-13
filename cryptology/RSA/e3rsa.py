#-*- coding：UTF-8 -*-



from random import randint
import random
import math
import sys
import argparse

def  charToAscii(message):       #将字符转化为ASCII码
  Output = []
  for i in message:
      Output.append(ord(i))
  return Output

def AsciiToHex(message):        #将ASCII码变为十六进制
  Output = ''
  for each in message:
    Output = Output + str(hex(each)).split('x')[1]
  return Output

def Hex_to_dec(hexnumber):        #16进制字符串转化为十进制
    decnumber = int(hexnumber,16)
    return decnumber

def dec_to_Hex(decumber):          #十进制转化为十六进制
    hexnumber = hex(decumber)
    return hexnumber


def big_P_Q():                  #产生两个大素数
    flag = 0
    while not flag:
        p = random.randrange(10**10,10**11)

        if charge_sushu_1(p) and _ack(2,p):

            q = random.randrange(p,10**11)
            if charge_sushu_1(q) and p != q and _ack(2,q):
                flag = 1
    return p,q

def fastExpMod(b, e, m):          #快速求模
    result = 1
    while e != 0:
        if (e&1) == 1:
            # ei = 1, then mul
            result = (result * b) % m
        e >>= 1
        # b, b^2, b^4, b^8, ... , b^(2^n)
        b = (b*b) % m
    return result

def gcd(a,b):                     #判断互素
    if a<b:
        a,b = b,a
    while b != 0:
        temp = a%b
        a = b
        b = temp
    return (a,b)


def find_e(En):                     #寻找e
    while 1:
        e = random.randrange(10000)
        if gcd(e,En) == (1,0):
            break

    return e

def find_d(e,s):                    #求d

    u1, u2, u3 = 1, 0, e
    v1, v2, v3 = 0, 1, s
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % s

def charge_sushu_1(n):
    Sushu = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41
                 , 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97)
    for y in Sushu:
        if n % y == 0:
            return False
    return True

def _ack(a,n):

    a1 = pow(17-a,n,n)
    a2 = pow(17,n,n) - (a%n)
    if a1 == a2:
        return 1
    else:
        return 0

def charge_sushu_2(n, k):
    if n < 2:
           return False
    d = n - 1
    r = 0
    while not (d & 1):
            r += 1
            d >>= 1
    for i in range(k):
            a = randint(120)        #随机数
            x = fastExpMod(a, d, n)
            if x == 1 or x == n - 1:
                    continue
            for i in range(r - 1):
                    x = fastExpMod(x, 2, n)
            if x == 1:
                    return False
            if x == n - 1:
                    break
    else:
            return False
    return True

def jiami(plainfile,nfile,efile,cipherfile):
    #print("-------测试数据加密--------\n")
    print("-------加密--------\n")
    with open(plainfile, 'r') as f:
        plaindata = f.read().strip('\n')
        print("读入的明文为：", plaindata)
        f.close()
    dec_plain = Hex_to_dec(plaindata)
    #print("明文十进制为：:", dec_plain)

    with open(nfile, 'r') as f:
        pubkey_n = f.readline().strip('\n')
        f.close()
    with open(efile,"r") as f:
        pubkey_e = f.readline().strip('\n')
        f.close()
    print("n为：", pubkey_n)
    print("e为：", pubkey_e)
    dec_e = Hex_to_dec(pubkey_e)
    print("e十进制为：", dec_e)
    dec_n = Hex_to_dec(pubkey_n)
    print("n十进制为：", dec_n)

    dec_cipher = fastExpMod(dec_plain, dec_e, dec_n)

    print(cipherfile, dec_cipher)
    cipher = dec_to_Hex(dec_cipher)
    str_cipher = str(cipher).upper()
    with open(cipherfile, 'w') as f:
        f.write(str_cipher[2:])
        f.close()
    print("密文为：", str_cipher[2:])


def qianming(plainfile,nfile,dfile,cipherfile):
    # print("-------测试数据加密--------\n")
    print("-------签名--------\n")
    with open(plainfile, 'r') as f:
        plaindata = f.read().strip('\n')
        print("读入的明文为：", plaindata)
        f.close()
    dec_plain = Hex_to_dec(plaindata)
    # print("明文十进制为：:", dec_plain)

    with open(nfile, 'r') as f:
        pubkey_n = f.readline().strip('\n')
        f.close()
    with open(dfile, "r") as f:
        pubkey_d = f.readline().strip('\n')
        f.close()
    print("n为：", pubkey_n)
    print("d为：", pubkey_d)
    dec_d = Hex_to_dec(pubkey_d)
    print("d十进制为：", dec_d)
    dec_n = Hex_to_dec(pubkey_n)
    print("n十进制为：", dec_n)

    dec_cipher = fastExpMod(dec_plain, dec_d, dec_n)

    print(cipherfile, dec_cipher)
    cipher = dec_to_Hex(dec_cipher)
    str_cipher = str(cipher).upper()
    with open(cipherfile, 'w') as f:
        f.write(str_cipher[2:])
        f.close()
    print("密文为：", str_cipher[2:])



if  __name__ == '__main__':

    parser = argparse.ArgumentParser(description='test')
    parser.add_argument('-p', '--plainfile', help='指定明文文件的位置和名称')
    parser.add_argument('-n', '--nfile', help='指定存放整数n的文件的位置和名称')
    parser.add_argument('-e', '--efile', help='在数据加密时，指定存放整数e的文件的位置和名称')
    parser.add_argument('-d', '--dfile', help='在数字签名时，指定存放整数d的文件的位置和名称')
    parser.add_argument('-c', '--cipherfile', help='指定密文文件的位置和名称')

    args = parser.parse_args()

    if args.dfile is None:
        jiami(args.plainfile,args.nfile,args.efile,args.cipherfile)
    else:
        qianming(args.plainfile,args.nfile,args.dfile,args.cipherfile)
    input() # os.system('pause')






