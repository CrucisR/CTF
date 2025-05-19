import base64

# 添加加密函数用于验证
def encrypt(plain_text, key_str):
    # 转换明文为字节
    plain_bytes = plain_text.encode('utf-8')
    
    # 处理密钥
    key_bytes = key_str.encode('utf-8')
    key_padded = key_bytes.ljust(16, b'\x00')[:16]
    k_int = c(key_padded, False)
    
    # 明文转int数组（含长度）
    m_int = c(plain_bytes, True)
    m = len(m_int) - 1  # 数据部分长度
    
    # 加密循环
    i3 = (52 // m) + 6
    i4 = m_int[m]  # 最后一个元素
    i5 = 0
    
    for _ in range(i3):
        i7 = (-1640531527) + i5  # 0x9E3779B9的补码
        i8 = (i7 >> 2) & 3
        
        # 正向处理每个元素
        i9 = i4
        for i10 in range(m):
            i11 = i10 + 1
            i9 = m_int[i10] + a(i7, m_int[i11 % m], i9, i10, i8, k_int)
            m_int[i10] = i9 & 0xFFFFFFFF  # 确保32位
        
        i5 = i7
        i4 = a(i5, m_int[0], i9, m, i8, k_int) + m_int[m]
        m_int[m] = i4 & 0xFFFFFFFF
    
    # int数组转字节
    encrypted_bytes = bytearray()
    for num in m_int:
        for _ in range(4):
            encrypted_bytes.append(num & 0xFF)
            num >>= 8
    
    # Base64编码
    return base64.b64encode(encrypted_bytes).decode('ascii')


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

# 在主程序中添加验证
if __name__ == "__main__":
    target_b64 = "u4jdb+9UH2RXBYKYjjKfA4OrmQvuikG89aXT5G+a1dhncN6QxzL6SA=="
    key = "flag{123456}"
    
    # 验证加密/解密一致性
    test_text = "test123"
    encrypted = encrypt(test_text, key)
    decrypted = decrypt(encrypted, key)
    
    print(f"测试加密结果: {encrypted}")
    print(f"测试解密结果: {decrypted}")
    
    # 尝试解密目标密文
    try:
        plain_text = decrypt(target_b64, key)
        print(f"解密成功！原始内容为: {plain_text}")
    except Exception as e:
        print(f"解密失败: {str(e)}")