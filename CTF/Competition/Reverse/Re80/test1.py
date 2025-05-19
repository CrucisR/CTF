import base64
import struct

def xxtea_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    # 密钥处理（填充至16字节）
    key = key.ljust(16, b'\0')[:16]
    key_arr = struct.unpack("<4I", key)  # 分解为4个32位整数
    
    # 数据转换
    v = list(struct.unpack("<%dI" % (len(ciphertext)//4), ciphertext))
    n = len(v)
    if n < 1:
        return ciphertext
    
    # 解密参数
    delta = 0x9E3779B9
    rounds = 6 + 52 // n
    sum_ = (delta * rounds) & 0xFFFFFFFF
    
    # 核心解密逻辑
    y = v[0]
    for _ in range(rounds):
        e = (sum_ >> 2) & 3
        for p in range(n-1, 0, -1):
            z = v[p-1]
            v[p] = (v[p] - (
                ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ 
                ((sum_ ^ y) + (key_arr[(p & 3) ^ e] ^ z))
            )) & 0xFFFFFFFF
            y = v[p]
        z = v[n-1]
        v[0] = (v[0] - (
            ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ 
            ((sum_ ^ y) + (key_arr[(0 & 3) ^ e] ^ z))
        )) & 0xFFFFFFFF
        y = v[0]
        sum_ = (sum_ - delta) & 0xFFFFFFFF
    
    # 转换回字节
    return b''.join(struct.pack("<I", num) for num in v)

# 使用示例
encrypted_b64 = "u4jdb+9UH2RXBYKYjjKfA4OrmQvuikG89aXT5G+a1dhncN6QxzL6SA=="
key = b"flag{123456}"

# 执行解密
ciphertext = base64.b64decode(encrypted_b64)
plaintext = xxtea_decrypt(ciphertext, key)

# 处理填充字节（根据原始加密逻辑可能需要调整）
flag = plaintext.rstrip(b"\x00").decode("utf-8")
print("Decrypted Flag:", flag)

# https://xiaoai.me/pages/dev-xxteacrypt

# 512c0195-5d8b-4c0a-b40a-fb9b680201e6

# -1640531527

# 512c0195-5d8b-4c0a-b40a-fb9b680201e6$

# https://sbox.cn/tool/xxtea