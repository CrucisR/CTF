from Crypto.Util.number import *
from sympy.ntheory import factorint
from gmpy2 import invert

# Provided values
pbar = 6163052460653484875222897871157214579695585174891162334492786197049974156163331261890110177547761022234329462136895755353549723084727441669764541927830678787635575660347
n1 = 19768100979643178970980222798514241427847019621885556714371417306890322413841759155705534740675505641218229128272878009360947016811255408216649419289094293346805021206562475574510447819185154841486638959169187323643703056356558087814806552256616914926631924571704104265274285060591175960523777901261693741556173545977822634199184934702888116805044900132944600846083977172319903839498719090224832707054269425475717758130694735545845648524802276601816827231690868680399305987918120731997093606128145918412651346475602662507731815533837986806539546744344871863963959358138574136679183367178701193757836744520971998033489
c1 = 10510704287421598064923207205443434987649107724961840980540099065383493172702132986990919118704302537850501494540050615373207280562745412929077036236441357066745184251162964131411221716516405523828174133408833061619307488453539707753144972451676202156737070312370001177385210347503280219978816663943757370721860107122948144254203283353095695514204913090647256169755811550374583701604668732607639771411216498112107507915894609138425855355533539795314642466254410740876956635185133792747649115488884248829618454725387044380868005976380847185801851017281198702986435528487365976639275461888993167549955183114098585027025

e = 65537

# Task 1: Recover p1
found = False
for k in range(2**(1024 - 562)):
    p1 = k * 2**562 + pbar
    if n1 % p1 == 0:
        q1 = n1 // p1
        if isPrime(q1):
            found = True
            break

if not found:
    raise ValueError("Failed to factorize n1 with given pbar")

phi_n1 = (p1 - 1) * (q1 - 1)
d1 = invert(e, phi_n1)
m1 = pow(c1, d1, n1)
m1_bytes = long_to_bytes(m1)

# Task 2: Recover p2, q2, and m2
# Similar steps need to be taken to factor n2 and recover m2

# Combine the results
flag = m1_bytes + m2_bytes
print(flag)