from Crypto.Util.number import inverse, long_to_bytes

# 给定的参数
N = 174614584514610929431396115941630384895178909723705718836862238095900829966738
n = 25734163146776863423334597563854508025295423350215772176197139108245197394099966778835320485200297366854897680006649
cp = 119835366288961698540579634520960353987
cq = 205217723185958485497338964538298567862
cr = 114342282872579112405953192140116908309
e = 65537
c = cp * cq * cr  # 合并密文

# 计算p和q的值
def factorize(n):
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return i, n // i

# 分解n得到p和q
p, q = factorize(n)

# 计算r
r = inverse(q, p)

# 使用CRT求解明文
mp = pow(cp, 1, p)
mq = pow(cq, 1, q)
mr = pow(cr, 1, r)

m = (mp * q * inverse(q, p) + mq * p * inverse(p, q) + mr * p * q * inverse(q, r)) % N

# 将解密后的明文转换为字节并打印
flag = long_to_bytes(m)
print(flag)
print(flag.decode())
