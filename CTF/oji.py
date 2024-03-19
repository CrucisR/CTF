def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('乘法逆元不存在')
    else:
        return x % m

# 请替换为您的实际值
ср = 119835366288961698540579634520960353987
cq = 205217723185958485497338964538298567862
cr = 114342282872579112405953192140116908309

p = 323220892738543152054341271709492856593
q = 264844933898895094781643605097884203033
r = 300620750405215104529267866758584282321

# 计算乘法逆元
mp = modinv(q*r, p)
mq = modinv(p*r, q)
mr = modinv(p*q, r)

# 求解 c
c = (ср*mp*q*r + cq*mq*p*r + cr*mr*p*q) % (p*q*r)

print("解出的 c 值为:", c)


