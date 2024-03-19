# from Crypto.Util.number import inverse, long_to_bytes

# # 给定的参数
# N = 174614584514610929431396115941630384895178909723705718836862238095900829966738
# n = 25734163146776863423334597563854508025295423350215772176197139108245197394099966778835320485200297366854897680006649
# cp = 119835366288961698540579634520960353987
# cq = 205217723185958485497338964538298567862
# cr = 114342282872579112405953192140116908309
# e = 65537
# c = cp * cq * cr  # 合并密文

# # 计算模数分解
# def factorize(n):
#     p_plus_q = n - N
#     p_minus_q = pow(p_plus_q, 2) - 4 * n
#     p = (p_plus_q + pow(p_minus_q, 0.5)) // 2
#     q = n // p
#     return p, q

# # 计算p和q
# p, q = factorize(n)

# # 计算r
# r = inverse(int(q), int(p))  # 传递整数参数

# # 使用CRT求解明文
# mp = pow(int(cp), int(e), int(p))
# mq = pow(int(cq), int(e), int(q))
# mr = pow(int(cr), int(e), int(r))
# # 计算模逆元
# q_inv_p = inverse(int(q), int(p))  # 传递整数参数
# p_inv_q = inverse(int(p), int(q))  # 传递整数参数
# q_inv_r = inverse(int(q), int(r))  # 传递整数参数

# m = (mp * q * q_inv_p + mq * p * p_inv_q + mr * p * q * q_inv_r) % N

# # 将解密后的明文转换为字节并打印
# flag = long_to_bytes(int(m))
# print(flag.hex())
# print(flag.decode('latin1'))


# flag = b'###'
# p = getPrime (128)
# q = getPrime (128)
# N = pow(p, 2)+ pow(q, 2)
# N = 174614584514610929431396115941630384895178909723705718836862238095900829966738


from sympy import factorint

N = 174614584514610929431396115941630384895178909723705718836862238095900829966738

# 对N进行因式分解，获取p和q
factors = factorint(N)
p, q = factors.keys()

print("p:", p)
print("q:", q)

