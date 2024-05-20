from Crypto.Util.number import *
import gmpy2
from multiprocessing import Pool

# Provided values for Task 2
v = 21811641343255983500381828224929413459990162361850958125383974234884106307873322539765955554263002248428935202562895865347202800040026789414846833621961327
n2 = 80770367920827999366561124806858072244868246530328531406042193928182500146180018588600031672448257079863184223921795979757349028463789221446358339745547043692750222588739400567530737810813398459822168705125460502585755974278493854596146452325614299258779463923215509726313171542464349985581821617990647624183
c2 = 56343782366102833380745295389213485175221491538534848704702375927613840775732575944761885136116674144349169787377556123570123828334442175961899563259853689100791589574300729801115267366815647384965461858231633069473434409311760232006811495812507586049512050751885791314256954159905987409748845237122699825479
e = 65537

# Fermat's Factorization
def fermat_factorization(n):
    a = gmpy2.isqrt(n)
    b2 = a * a - n
    b = gmpy2.isqrt(b2)
    count = 0
    while b * b != b2:
        a += 1
        b2 = a * a - n
        b = gmpy2.isqrt(b2)
        count += 1
        if count % 1000000 == 0:
            print(f"Still working, count: {count}")
    return int(a + b), int(a - b)

# Parallelized Fermat Factorization
def parallel_fermat(n, num_processes=4):
    with Pool(num_processes) as p:
        results = p.starmap(fermat_factorization, [(n,)] * num_processes)
        for result in results:
            if result:
                return result
    return None

# Recover p2 and q2
p2, q2 = parallel_fermat(n2)
if not p2 or not q2:
    raise ValueError("Failed to factorize n2")

# Compute phi(n2) and d2
phi_n2 = (p2 - 1) * (q2 - 1)
d2 = pow(e, -1, phi_n2)
m2 = pow(c2, d2, n2)
m2_bytes = long_to_bytes(m2)

# Combine the results to get the flag
flag = m1_bytes + m2_bytes
print(f"Flag: {flag}")
