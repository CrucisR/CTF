import base64

# 定义无符号右移函数
def unsigned_right_shift(n, b):
    return (n & 0xFFFFFFFF) >> b

# 实现a方法（与Java逻辑一致）
def a(i2, i3, i4, i5, i6, iArr):
    idx = (i5 & 3) ^ i6
    term1 = (i2 ^ i3) + (iArr[idx] ^ i4)
    term1 %= 0x100000000  # 模拟32位溢出
    
    part1 = (unsigned_right_shift(i4, 5) ^ (i3 << 2)) & 0xFFFFFFFF
    part2 = (unsigned_right_shift(i3, 3) ^ (i4 << 4)) & 0xFFFFFFFF
    term2 = (part1 + part2) % 0x100000000
    
    result = (term1 ^ term2) & 0xFFFFFFFF
    if result > 0x7FFFFFFF:
        result -= 0x100000000  # 转换为有符号整数
    return result

# 实现c方法（字节数组转int数组，支持长度标记）
def c(bArr, z3):
    length = len(bArr)
    m = (length // 4) + (1 if length % 4 else 0)
    int_arr = [0] * (m + 1 if z3 else m)  # z3=true时多一个长度元素
    
    for i in range(length):
        byte = bArr[i]
        idx = i // 4
        shift = (i % 4) * 8
        int_arr[idx] |= byte << shift
    
    if z3:
        int_arr[-1] = length  # 最后一位存储原始长度
    return int_arr

def decrypt(cipher_b64, key_str):
    # 1. 解码Base64密文
    cipher_bytes = base64.b64decode(cipher_b64)
    
    # 2. 处理密钥（填充到16字节，Java逻辑为左填充0）
    key_bytes = key_str.encode('utf-8')
    key_padded = key_bytes.ljust(16, b'\x00')[:16]  # 右填充0，与Java一致
    k_int = c(key_padded, False)  # 密钥不需要长度标记
    
    # 3. 密文转int数组（包含长度标记，对应加密时的c3）
    m_int = c(cipher_bytes, True)  # 关键修复：z3=True，包含长度
    data_len = len(m_int) - 1       # 数据部分长度（排除最后一个长度元素）
    if data_len < 1:
        raise ValueError("密文数据过短")
    
    m = data_len
    i3 = (52 // m) + 6  # 加密时的循环次数
    
    # 4. 逆向加密循环（注意：最后一个元素是长度，不参与运算）
    for t in range(i3-1, -1, -1):
        i7 = t * 0x9E3779B9  # RC5常数
        i8 = (i7 >> 2) & 3
        
        # 先处理最后一个数据元素（索引m-1，长度元素在m位置）
        i9_prev = m_int[m]  # 暂存下一轮的i9（当前不参与运算）
        delta_last = a(i7, m_int[0], m_int[m-1], m-1, i8, k_int)
        m_int[m-1] = (m_int[m-1] - delta_last) % 0x100000000
        
        # 逆序处理前m-1个元素
        for i10 in range(m-2, -1, -1):
            delta = a(i7, m_int[i10+1], m_int[i10], i10, i8, k_int)
            m_int[i10] = (m_int[i10] - delta) % 0x100000000
    
    # 5. 提取明文长度和数据
    plain_length = m_int[-1]  # 最后一个元素是原始明文长度
    plain_int_arr = m_int[:-1]  # 去除长度标记，保留数据
    
    # 6. int数组转字节数组（小端序）
    plain_bytes = bytearray()
    for num in plain_int_arr:
        for _ in range(4):
            plain_bytes.append(num & 0xFF)
            num >>= 8
    
    # 按原始长度截取字节数组
    plain_bytes = plain_bytes[:plain_length]
    
    # 转换为UTF-8字符串（处理可能的非法字节，这里强制解码）
    return plain_bytes.decode('utf-8', errors='strict')  # strict模式检查合法性

# 主程序
if __name__ == "__main__":
    target_b64 = "u4jdb+9UH2RXBYKYjjKfA4OrmQvuikG89aXT5G+a1dhncN6QxzL6SA=="
    key = "flag{123456}"
    
    try:
        plain_text = decrypt(target_b64, key)
        print(f"解密成功！原始内容为: {plain_text}")
        # 验证：正确结果应为符合flag格式的字符串
        if plain_text.startswith("flag{") and plain_text.endswith("}"):
            print(f"Flag：{plain_text}")
    except Exception as e:
        print(f"解密失败: {str(e)}")