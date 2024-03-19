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
def find_p_and_q(N, n):
    # 从平方和的一半开始搜索
    start = int((N ** 0.5) / 2)
    for p in range(start, N):
        q_squared = N - p ** 2
        q = pow(q_squared, 1, n)
        if q * p == n:
            return p, q
    return None, None

# 找到p和q
p, q = find_p_and_q(N, n)

if p is not None and q is not None:
    # 计算r
    r = inverse(q, p)

    mp = pow(cp, 1, p)
    mq = pow(cq, 1, q)
    mr = pow(cr, 1, r)

    m = (mp * q * inverse(q, p) + mq * p * inverse(p, q) + mr * p * q * inverse(q, r)) % N

    # 将解密后的明文转换为字节并打印
    flag = long_to_bytes(m)
    print(flag)
    print(flag.decode())
else:
    print("未找到合适的p和q。")




# from Crypto.Util.number import *

# flag = b'###'
# p = getPrime (128)
# q = getPrime (128)
# r = getPrime (128)
# n = p * q* r
# N = pow(p, 2)+ pow(q, 2)
# e = 65537
# #enc
# c = pow(bytes_to_long(flag),e,n)
# ср = c%p
# cq = c%q
# cr = c%r
# # print (N,n, cp, cq, cr)
# N = 174614584514610929431396115941630384895178909723705718836862238095900829966738
# n = 25734163146776863423334597563854508025295423350215772176197139108245197394099966778835320485200297366854897680006649
# ср = 119835366288961698540579634520960353987
# cq = 205217723185958485497338964538298567862
# cr = 114342282872579112405953192140116908309
