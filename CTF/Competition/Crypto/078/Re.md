
## re

## WP 

```
import base64

def decode_custom_base64(encoded_str):
    # 修正后的自定义表（64字符）
    custom_table = "0123456789ABCDEFGHIJKLMN@PQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
    std_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    # 确保长度一致
    assert len(custom_table) == len(std_table), "字符表长度必须相同"
    
    translated = encoded_str.translate(str.maketrans(custom_table, std_table))
    missing_padding = 4 - (len(encoded_str) % 4)
    if missing_padding != 4:
        translated += "=" * missing_padding
    return base64.b64decode(translated)

def reverse_xor(modified_bytes):
    original = []
    for i in range(len(modified_bytes)):
        if i % 2 == 0:
            original.append(modified_bytes[i] ^ i)
        else:
            original.append(modified_bytes[i] ^ i ^ 42)
    return bytes(original)

# 示例用法
encoded_str = "替换为实际编码字符串"
modified_flag = decode_custom_base64(encoded_str)
flag = reverse_xor(modified_flag)
print(flag.decode())
```