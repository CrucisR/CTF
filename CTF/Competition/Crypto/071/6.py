from sage.all import *
from Crypto.Util.number import long_to_bytes, bytes_to_long

n1 = 19768100979643178970980222798514241427847019621885556714371417306890322413841759155705534740675505641218229128272878009360947016811255408216649419289094293346805021206562475574510447819185154841486638959169187323643703056356558087814806552256616914926631924571704104265274285060591175960523777901261693741556173545977822634199184934702888116805044900132944600846083977172319903839498719090224832707054269425475717758130694735545845648524802276601816827231690868680399305987918120731997093606128145918412651346475602662507731815533837986806539546744344871863963959358138574136679183367178701193757836744520971998033489
pbar = 6163052460653484875222897871157214579695585174891162334492786197049974156163331261890110177547761022234329462136895755353549723084727441669764541927830678787635575660347
c1 = 10510704287421598064923207205443434987649107724961840980540099065383493172702132986990919118704302537850501494540050615373207280562745412929077036236441357066745184251162964131411221716516405523828174133408833061619307488453539707753144972451676202156737070312370001177385210347503280219978816663943757370721860107122948144254203283353095695514204913090647256169755811550374583701604668732607639771411216498112107507915894609138425855355533539795314642466254410740876956635185133792747649115488884248829618454725387044380868005976380847185801851017281198702986435528487365976639275461888993167549955183114098585027025
e = 65537

k = var('k')
p1 = pbar + k * 2^562
n1_factors = n1.factors(limit=2^462)

# Use Coppersmith's method to find small root
PR.<x> = PolynomialRing(Zmod(n1), implementation='NTL')
f = (pbar + x*2^562)
roots = f.small_roots(X=2^462, beta=0.4)
for root in roots:
    p1_candidate = int(pbar + root*2^562)
    if n1 % p1_candidate == 0:
        p1 = p1_candidate
        q1 = n1 // p1
        if is_prime(q1):
            print(f"Found p1: {p1}")
            print(f"Found q1: {q1}")
            break

phi_n1 = (p1 - 1) * (q1 - 1)
d1 = inverse_mod(e, phi_n1)
m1 = pow(c1, d1, n1)
m1_bytes = long_to_bytes(m1)
print(f"Decrypted m1: {m1_bytes}")