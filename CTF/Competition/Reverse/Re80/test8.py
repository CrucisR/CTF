import base64
from ctypes import c_uint32

def little_endian_decrypt(ciphertext_base64, key_str):
    # Base64解码（兼容URL安全字符）
    ciphertext = base64.urlsafe_b64decode(ciphertext_base64 + '==='[: (4 - len(ciphertext_base64) % 4) % 4])
    
    # 密钥处理（小端序转换）
    key_bytes = key_str.encode('utf-8').ljust(16, b'\x00')[:16]
    key = [int.from_bytes(key_bytes[i:i+4], 'little') for i in range(0, 16, 4)]  # 网页5的小端序处理
    
    # 转换密文为32位整数数组（小端序）
    data = []
    for i in range(0, len(ciphertext), 4):
        chunk = ciphertext[i:i+4].ljust(4, b'\x00')
        data.append(int.from_bytes(chunk, byteorder='little'))  # 网页5的UTF-16小端序逆向
    
    # XXTEA逆向核心算法（动态轮次）
    n = len(data) - 1  # 排除末尾长度标记
    rounds = 6 + 52 // n
    sum_val = c_uint32(rounds * 0x9E3779B9)  # 固定DELTA值
    
    for _ in range(rounds):
        e = (sum_val.value >> 2) & 3
        for p in range(n, 0, -1):
            z = data[p-1]
            y = data[p]
            # 混淆函数逆向（参考网页3的数学逆向）
            mx = (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ 
                 ((sum_val.value ^ y) + (key[(p & 3) ^ e] ^ z)))
            data[p] = c_uint32(data[p] - mx).value  # 网页1的溢出处理
        sum_val.value -= 0x9E3779B9
    
    # 转换字节并处理填充（小端序逆向）
    decrypted = b''.join(num.to_bytes(4, 'little') for num in data)
    length = int.from_bytes(decrypted[-4:], 'little')  # 网页5的小端序长度提取
    return decrypted[:length].decode('utf-8', errors='ignore')

# 使用示例
if __name__ == "__main__":
    encrypted_data = "u4jdb+9UH2RXBYKYjjKfA4OrmQvuikG89aXT5G+a1dhncN6QxzL6SA=="
    secret_key = "flag{123456}"
    
    try:
        plaintext = little_endian_decrypt(encrypted_data, secret_key)
        print(f"解密结果: {plaintext}")
    except Exception as e:
        print(f"解密失败: {str(e)}")