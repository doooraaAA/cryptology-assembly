from base64 import b64encode

from Cryptodome.Random import get_random_bytes
from gmssl import sm4
import argparse
from Utils.sm2Util import SM2Util
from Utils.sm4Util import sm4_encode, sm4_decode
from Utils.sm3Util import sm3_hash
import os
import random

# 参数处理
parser = argparse.ArgumentParser()
parser.add_argument('-f', default='./test.txt', type=str)  # 命令行中指定甲读取明文位置
parser.add_argument('-yif', default='./message.txt', type=str)  # 命令行中指定乙接收明文位置
parser.add_argument('-k', default='./sm4_key.txt', type=str)  # 命令行中指定甲SM4密钥（加密前）位置
parser.add_argument('-ck',default='./sm4_key_encrypto.txt',type=str) # 命令行中指定SM4的密钥（加密后）的位置
parser.add_argument('-yk', default='./yi_sm4_key.txt', type=str)  # 命令行中指定乙SM4密钥（解密后）位置
parser.add_argument('-pri', default='./priKey.txt', type=str)  # 命令行中指定乙的私钥位置
parser.add_argument('-pub', default='./pubKey.txt', type=str)  # 命令行中指定乙的公钥位置
parser.add_argument('-iv', default='./iv.txt', type=str)  # 命令行中指定初始向量位置
parser.add_argument('-c', default='./test_cryp.txt', type=str)  # 命令行中指定密文位置
parser.add_argument('-ha', default='./hash.txt', type=str)  # 命令行中指定哈希文件位置
parser.add_argument('-si', default='./sign.txt', type=str)  # 命令行中指定签名文件位置
parser.add_argument('-jpri',default='./jiaPri.txt',type=str) # 命令行中指定甲的私钥位置
parser.add_argument('-jpub',default='./jiaPub.txt',type=str) # 命令行中指定甲的公钥位置


args = parser.parse_args()
plain_path = args.f
key_path = args.k
priKey_path = args.pri
pubKey_path = args.pub
iv_path = args.iv
cryp_path = args.c
hash_path = args.ha
sign_path = args.si
jiaPri_path = args.jpri
jiaPub_path = args.jpub
key_encry_path = args.ck
y_plain_path=args.yif
yi_key_path=args.yk

# 生成公私钥，将公钥传给对方
# 生成乙的公私钥对
e = SM2Util.GenKeyPair(None)
# 保存乙的公私钥对
with open(priKey_path,'w') as x:
    x.write(e[0])
with open(pubKey_path,'w') as x:
    x.write(e[1])
#乙将乙公钥传给甲

# 生成甲的公私钥对
e = SM2Util.GenKeyPair(None)
# 保存甲的公私钥对
with open(jiaPri_path,'w') as x:
    x.write(e[0])

with open(jiaPub_path,'w') as x:
    x.write(e[1])
# 甲将甲公钥传给乙

print("对于甲（请等待）")

#生成随机明文
file = open(plain_path, "w", encoding="utf-8")
filesize = os.path.getsize(plain_path)
while filesize < 5*1024*1024:
    file.write(str(random.randint(999999999, 99999999999)))
    filesize = os.path.getsize(plain_path)
#这是为了补齐位数，避免报错
if filesize%16!=0:
    last=16-(filesize%16)
    for i in range (0,last):
        file.write(str(0))
print("甲生成消息\n随机数据已写入" + plain_path + "文件大小：5MB" )

# 生成SM4的128位SM4随机密钥
sm4_key_bytes = get_random_bytes(16)  # 16字节，即128位
sm4_key = b64encode(sm4_key_bytes).decode('utf-8')
print("未加密的SM4秘钥为："+sm4_key)
with open(key_path, "w") as x:
    x.write(sm4_key)

# 甲使用乙的公钥对SM4密钥进行加密
with open(pubKey_path,"r") as x:
    pubKey=x.read()
with open(key_path,"r") as x:
    sm4_key=x.read()
sm4EnCry = SM2Util(pub_key=pubKey)
key_crypto = sm4EnCry.Encrypt(sm4_key)
with open(key_encry_path,'w')as x:
    x.write(key_crypto)
print("加密后SM4的秘钥为："+key_crypto)
# 将加密后的SM4秘钥发给乙


# 生成初始向量文件
iv_bytes = get_random_bytes(16)
iv = b64encode(iv_bytes).decode('utf-8')
with open(iv_path,'w') as x:
    x.write(iv)

#甲加密明文
with open(plain_path, 'r') as x:
    plain = x.read()
with open(iv_path, 'r') as x:
    iv = x.read()
with open(key_path, 'r') as x:
    sm4_key = x.read()
#print("加密前明文为："+plain)
miwen = sm4_encode(sm4_key, plain, iv)
#print("甲加密并传给乙的密文为："+miwen)
print("甲向乙传送密文（请等待）")
with open(cryp_path, 'w') as x:
    cryp = x.write(miwen)
#获取甲的公私钥，以对明文哈希值进行签名
with open(jiaPri_path,'r') as x:
    jiaPri = x.read()
with open(jiaPub_path,'r') as x:
    jiaPub = x.read()
jiaSign = SM2Util(pri_key=jiaPri,pub_key=jiaPub[2:])
# 获取明文的哈希值
plainHash = sm3_hash(plain.encode())
jiaSign_str = jiaSign.Sign(plainHash)
# 将签名文件写入文件中
with open(sign_path,'w')as x:
    x.write(jiaSign_str)
print("甲向乙传送签名："+jiaSign_str)


print("对于乙：")
# 获取乙SM2公私钥对
with open(priKey_path, 'r') as pri:
    priKey = pri.read()
with open(pubKey_path, 'r') as pub:
    pubKey = pub.read()
# 获得SM2对象
sm2 = SM2Util(pri_key=priKey, pub_key=pubKey[2:])
# 加密SM4的密钥
# sm4_key_encrypto = sm2.Encrypt(sm4_key)
# with open("sm4_key_encrypto.txt",'w') as sm4En:
#     sm4En.write(sm4_key_encrypto)

# 对SM4的密钥进行解密
with open(key_encry_path, 'r') as sm4En:
    sm4_key_encrypto = sm4En.read()
    yi_sm4_key = sm2.Decrypt(sm4_key_encrypto)

print("未解密的SM4密钥为：" + sm4_key_encrypto)
print("解密过后的SM4密钥为" + yi_sm4_key)
# 保存解密过后的密钥
with open(yi_key_path, 'w') as x:
    x.write(yi_sm4_key)

# 使用获得的SM4密钥来解密文件
# 读取密文
with open(cryp_path, 'r') as x:
    cryp = x.read()
print("乙接收甲密文（请等待）")
# 获取初始向量文件
with open(iv_path, 'r') as x:
    iv = x.read()
# 解密
message = sm4_decode(yi_sm4_key, cryp, iv)
#print("原密文为：" + cryp)
#print("解密过后的明文为：" + message)
# 保存解密的明文
with open(y_plain_path, 'w') as x:
    x.write(message)

# 下面对甲的签名进行验证
# 获取签名文件

with open(sign_path, 'r') as x:
    sign = x.read()
# 获取哈希值
hashCode = sm3_hash(message.encode())
# 获取甲的公钥
with open(jiaPub_path,'r') as x:
    jiaPub = x.read()

jiaVery = SM2Util(pub_key=jiaPub[2:])
check=jiaVery.Verify(hashCode,sign)
# with open(hash_path, 'r') as x:
#     hashCode = x.read()
# 输出验证结果
print("签名验证的结果为："+str(check))

# 检验恢复过后的明文和原来的明文是否一致
# 获取原来的明文
with open(plain_path, 'r') as x:
    plain = x.read()
if message == plain:
    print("一致性检测的结果为：success")
else:
    print("一致性检测的结果为：failure")


