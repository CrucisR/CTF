import base64
from ctypes import c_uint32

def decrypt(ciphertext_base64, key_str):
    # Base64解码
    ciphertext = base64.b64decode(ciphertext_base64)
    
    # 密钥处理（与Java的c方法一致）
    key_bytes = key_str.encode('utf-8').ljust(16, b'\x00')[:16]
    key = [bytes_to_int(key_bytes[i:i+4]) for i in range(0,16,4)]
    
    # 转换密文为int数组（小端序）
    data = []
    for i in range(0, len(ciphertext), 4):
        chunk = ciphertext[i:i+4].ljust(4, b'\x00')
        data.append(bytes_to_int(chunk))
    
    # 动态计算轮次（与Java的(52/length)+6一致）
    n = len(data) - 1  # 排除末尾的长度标记
    rounds = 6 + 52 // n
    sum = c_uint32(rounds * 0x9E3779B9)  # DELTA常量
    
    # 逆向加密流程
    for _ in range(rounds):
        e = (sum.value >> 2) & 3
        for p in range(n, 0, -1):
            z = data[p-1]
            y = data[p]
            mx = (((z >> 5 ^ y << 2) + 
                  (y >> 3 ^ z << 4)) ^ 
                  ((sum.value ^ y) + 
                  (key[(p & 3) ^ e] ^ z)))
            data[p] = c_uint32(data[p] - mx).value
        sum.value -= 0x9E3779B9
    
    # 转换字节并处理填充
    decrypted = b''.join(int_to_bytes(num) for num in data)
    length = bytes_to_int(decrypted[-4:])  # 提取原始长度
    return decrypted[:length].decode('utf-8', errors='ignore')

def bytes_to_int(b):
    return int.from_bytes(b, 'little')

def int_to_bytes(n):
    return n.to_bytes(4, 'little')

# 使用示例
if __name__ == "__main__":
    cipher = "u4jdb+9UH2RXBYKYjjKfA4OrmQvuikG89aXT5G+a1dhncN6QxzL6SA=="
    key = "flag{123456}"
    print("解密结果:", decrypt(cipher, key))