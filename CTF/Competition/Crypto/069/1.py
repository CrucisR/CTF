from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import long_to_bytes

# 已知参数
p = 7009055691271085017633552549787410731913992253774387425490387612557670476299
q = 286946190247973980505644138206073414772402245341092646992350442672553994876957
e = 65537
ciphertext = 17858908734833281413766792387351158123556951294658230627154128012251611732190945146345434563063304236989621568202562959443862216042485017454585240776787955

# 计算 n
n = p * q

# 创建RSA对象
key = RSA.construct((n, e))

# 创建PKCS1_OAEP密码对象
cipher_rsa = PKCS1_OAEP.new(key)

# 使用私钥解密密文
plaintext = cipher_rsa.decrypt(long_to_bytes(ciphertext))

print("解密后的明文:", plaintext.decode())
