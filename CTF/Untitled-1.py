from Crypto.Util.number import inverse, long_to_bytes

# 给定的参数
N = 174614584514610929431396115941630384895178909723705718836862238095900829966738
n = 25734163146776863423334597563854508025295423350215772176197139108245197394099966778835320485200297366854897680006649
cp = 119835366288961698540579634520960353987
cq = 205217723185958485497338964538298567862
cr = 114342282872579112405953192140116908309
e = 65537
c = cp * cq * cr  # 合并密文

# 计算模数分解
def factorize(n):
    p_plus_q = n - N
    p_minus_q = pow(p_plus_q, 2) - 4 * n
    p = (p_plus_q + pow(p_minus_q, 0.5)) // 2
    q = n // p
    return p, q

# 计算p和q
p, q = factorize(n)

# 计算r的模逆元
r = inverse(int(q), int(p))  # 传递整数参数

# 使用CRT求解明文
mp = cp % p
mq = cq % q
mr = cr % r

# 计算模逆元
q_inv_p = inverse(int(q), int(p))  # 传递整数参数
p_inv_q = inverse(int(p), int(q))  # 传递整数参数
q_inv_r = inverse(int(q), int(r))  # 传递整数参数

m = (mp * q * q_inv_p + mq * p * p_inv_q + mr * p * q * q_inv_r) % N

# 将解密后的明文转换为字节并打印
flag = long_to_bytes(int(m))  # 将解密结果转换为整数
print(flag.decode('latin1'))
# print(flag.decode('ascii'))
print(flag.decode('ISO-8859-1'))
# print(flag.decode('utf-8'))
print(flag.hex())

hex_string = "5a2773b87383c8000000000000000000"

# 将十六进制字符串转换为字节
byte_data = bytes.fromhex(hex_string)

# 使用不同的编码尝试解码字节数据
for encoding in ["ascii", "latin1", "ISO-8859-1"]:
    try:
        decoded = byte_data.decode(encoding)
        print(f"Decoded with {encoding}: {decoded}")
    except Exception as e:
        print(f"Failed to decode with {encoding}: {e}")


# Z's¸sÈ
# Z's¸sÈ
# 5a2773b87383c8000000000000000000
# Failed to decode with ascii: 'ascii' codec can't decode byte 0xb8 in position 3: ordinal not in range(128)
# Decoded with latin1: Z's¸sÈ
# Decoded with ISO-8859-1: Z's¸sÈ