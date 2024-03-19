ciphertext = 9966997572481264848811933388191940583713155493833205990407647323504663705186233906872934419523662482269964905511764
出= 13040004482819735534037615230330787811236581066879395081779403395391685903042397789585945725


# 将数字转换为字符串
plaintext = str(ciphertext)

# # 将字符串按每两个字符分割，并转换为对应的 ASCII 字符
# flag = ""
# for i in range(0, len(plaintext), 2):
#     flag += chr(int(plaintext[i:i+2]))

# print("Flag:", flag)

# import base64

# # 将数字转换为字节串
# plaintext_bytes = str(ciphertext).encode()

# # 尝试进行 Base64 解码
# try:
#     flag = base64.b64decode(plaintext_bytes).decode()
#     print("Flag (Base64解码):", flag)
# except Exception as e:
#     print("Base64解码失败:", str(e))

# import base64

# # 尝试进行 Base32 解码
# try:
#     flag = base64.b32decode(plaintext_bytes).decode()
#     print("Flag (Base32解码):", flag)
# except Exception as e:
#     print("Base32解码失败:", str(e))


# 尝试将数字按十六进制解码
try:
    flag = bytes.fromhex(plaintext).decode()
    print("Flag (十六进制解码):", flag)
except Exception as e:
    print("十六进制解码失败:", str(e))
