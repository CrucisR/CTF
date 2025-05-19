import base64

# 无符号右移（模拟Java的>>>操作）
def unsigned_right_shift(n, b):
    return (n & 0xFFFFFFFF) >> b

# 实现Java中的a方法（核心运算）
def java_a(i2, i3, i4, i5, i6, key_int):
    idx = (i5 & 3) ^ i6
    term1 = (i2 ^ i3) + (key_int[idx] ^ i4)
    term1 &= 0xFFFFFFFF  # 保持32位
    
    part1 = (unsigned_right_shift(i4, 5) ^ (i3 << 2)) & 0xFFFFFFFF
    part2 = (unsigned_right_shift(i3, 3) ^ (i4 << 4)) & 0xFFFFFFFF
    term2 = (part1 + part2) & 0xFFFFFFFF
    
    return (term1 ^ term2) & 0xFFFFFFFF

# 字节数组转int数组（支持长度标记）
def bytes_to_int_array(byte_arr, with_length=True):
    length = len(byte_arr)
    int_len = (length + 3) // 4  # 向上取整到4字节块
    int_arr = [0] * (int_len + 1 if with_length else int_len)
    
    for i in range(length):
        byte = byte_arr[i]
        pos = i // 4
        shift = (3 - (i % 4)) * 8  # 大端序，高位在前
        int_arr[pos] |= (byte << shift) & 0xFFFFFFFF
    
    if with_length:
        int_arr[-1] = length  # 最后一位存储原始长度
    return int_arr

# int数组转字节数组（大端序）
def int_array_to_bytes(int_arr, length=None):
    byte_arr = bytearray()
    for num in int_arr:
        for _ in range(4):
            byte_arr.append((num >> 24) & 0xFF)  # 取最高位字节
            num <<= 8
            num &= 0xFFFFFFFF  # 保持32位
    
    if length is not None:
        byte_arr = byte_arr[:length]  # 按原始长度截取
    return byte_arr

def decrypt(cipher_b64, key_str):
    # 1. 处理密钥（固定16字节，左填充0）
    key_bytes = key_str.encode('utf-8')
    key_padded = key_bytes.ljust(16, b'\x00')[:16]
    key_int = bytes_to_int_array(key_padded, with_length=False)
    
    # 2. 解码密文并转换为int数组（包含长度标记）
    cipher_bytes = base64.b64decode(cipher_b64)
    cipher_int = bytes_to_int_array(cipher_bytes, with_length=True)
    
    data_len = len(cipher_int) - 1  # 数据部分长度（排除最后一个长度元素）
    if data_len < 1:
        raise ValueError("密文无效")
    
    m = data_len
    loop_count = (52 // m) + 6  # 与加密时的循环次数一致
    
    # 3. 逆向加密循环
    for t in range(loop_count-1, -1, -1):
        i7 = t * 0x9E3779B9  # RC5常数（加密时为-0x61C88647的补码）
        i8 = (i7 >> 2) & 3
        
        # 先处理最后一个数据元素（索引m-1）
        last_val = cipher_int[m-1]
        delta = java_a(i7, cipher_int[0], last_val, m-1, i8, key_int)
        cipher_int[m-1] = (last_val - delta) & 0xFFFFFFFF
        
        # 逆序处理前m-1个元素
        for i in range(m-2, -1, -1):
            curr_val = cipher_int[i]
            next_val = cipher_int[i+1]
            delta = java_a(i7, next_val, curr_val, i, i8, key_int)
            cipher_int[i] = (curr_val - delta) & 0xFFFFFFFF
    
    # 4. 提取明文长度和字节数组
    plain_length = cipher_int[-1]
    plain_int = cipher_int[:-1]  # 去除长度标记
    plain_bytes = int_array_to_bytes(plain_int, plain_length)
    
    # 5. 尝试解码（优先UTF-8，失败则尝试Latin-1）
    try:
        return plain_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return plain_bytes.decode('latin-1', errors='replace')

# 主程序（示例）
if __name__ == "__main__":
    # 目标密文（题目提供）
    target_cipher = "u4jdb+9UH2RXBYKYjjKfA4OrmQvuikG89aXT5G+a1dhncN6QxzL6SA=="
    # 题目中的密钥
    key = "flag{123456}"
    
    try:
        plain_text = decrypt(target_cipher, key)
        print("解密结果：", plain_text)
        
        # 验证是否为合法flag格式
        if plain_text.startswith("flag{") and plain_text.endswith("}"):
            print("成功获取Flag：", plain_text)
        else:
            print("警告：结果可能不是正确的flag格式")
    
    except Exception as e:
        print("解密失败：", str(e))
        # 输出原始字节的十六进制（用于调试）
        print("原始字节（十六进制）：", cipher_bytes.hex())