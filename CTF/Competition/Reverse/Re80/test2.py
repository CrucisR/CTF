import base64
from ctypes import c_uint32

def decrypt(ciphertext_base64, key_str):
    # Base64解码
    ciphertext = base64.b64decode(ciphertext_base64)
    
    # 密钥处理（填充至16字节并转为4个32位整数）
    key_bytes = key_str.encode('utf-8').ljust(16, b'\0')[:16]
    key = [int.from_bytes(key_bytes[i:i+4], 'little') for i in range(0,16,4)]
    
    # 转换密文为32位整数数组（小端序）
    data = [int.from_bytes(ciphertext[i:i+4], 'little') 
            for i in range(0, len(ciphertext), 4)]
    
    # XXTEA解密核心算法
    delta = 0x9E3779B9
    n = len(data)
    rounds = 6 + 52 // n
    total = c_uint32(rounds * delta)
    
    for _ in range(rounds):
        e = (total.value >> 2) & 3
        for p in reversed(range(n)):
            z = data[p-1] if p>0 else data[n-1]
            y = data[p]
            mx = (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ 
                 ((total.value ^ y) + (key[(p & 3) ^ e] ^ z)))
            data[p] = c_uint32(data[p] - mx).value
        total.value -= delta
    
    # 转换为字节数组（小端序）
    decrypted = b''.join(
        num.to_bytes(4, 'little') for num in data
    ).rstrip(b'\x00')  # 移除PKCS7填充
    
    return decrypted.decode('utf-8', errors='ignore')

# 使用示例
cipher = "u4jdb+9UH2RXBYKYjjKfA4OrmQvuikG89aXT5G+a1dhncN6QxzL6SA=="
key = "flag{123456}"

try:
    flag = decrypt(cipher, key)
    print(f"Decrypted Flag: {flag}")
except Exception as e:
    print(f"解密失败: {str(e)}")