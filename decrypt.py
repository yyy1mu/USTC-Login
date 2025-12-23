import base64
import json
import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
import os

# --- 配置信息 ---
TARGET_URL = "https://id.ustc.edu.cn"
TARGET_URL = TARGET_URL + "/gate/linkid/api/user/log/self/ssoLogin"
# 前端代码中的 RSA 公钥
RSA_PUBLIC_KEY_STR = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjVr1zKwohU3xA0afprWLSQvIymaSH/V27MedFc+CecXSnORIFMAp4uEIb4taDq/2X4eMeTI66Mu/rB5GKSFDbExF2Gu4NaO/CNDpf1gHMScUrIFCh4CDqzBnx17kclvezLkIK0T8FVa4cRsINvzjbnA6jUSMaf6Fm1n9wTAtW6QYBjssGOEtCj+c38PTBdFMmJbXp3brt1tEBesz6lb3Fjp76FGvDZ08xtYG8fxYPuiMwKU04eS+mcX/BunwgpU3zwekHYB+PWRIvq0lBry9Wms25sJE5T/RAv5fEuMLbBkfcZK3+7ivSZthTmPpr2Ap/ji70ZZ6u2jvR5VJq+LJHQIDAQAB
-----END PUBLIC KEY-----"""


def encrypt_request(data_dict):
    # 1. 生成 16 字节随机 AES 密钥并转为 Base64 (对应前端 WordArray.random)
    raw_aes_key = os.urandom(16)
    aes_key_base64 = base64.b64encode(raw_aes_key).decode('utf-8')

    # 2. 使用 RSA 公钥加密这个 Base64 后的 AES 密钥 (对应前端 privateKey)
    rsa_key = RSA.import_key(RSA_PUBLIC_KEY_STR)
    cipher_rsa = PKCS1_v1_5.new(rsa_key)
    # 前端是用 n.encrypt(e) 加密了字符串形式的 aes_key_base64
    encrypted_rsa_key = cipher_rsa.encrypt(aes_key_base64.encode('utf-8'))
    private_key_header = base64.b64encode(encrypted_rsa_key).decode('utf-8')

    # 3. 使用 AES-ECB 加密请求体 (对应前端 s 变量)
    # 前端先 JSON.stringify(body)

    if isinstance(data_dict, str):
        plain_text = data_dict
    else:
        plain_text = json.dumps(data_dict, separators=(',', ':'))

    cipher_aes = AES.new(raw_aes_key, AES.MODE_ECB)
    # Pkcs7 填充
    padded_data = pad(plain_text.encode('utf-8'), AES.block_size, style='pkcs7')
    encrypted_body = cipher_aes.encrypt(padded_data)
    final_body_base64 = base64.b64encode(encrypted_body).decode('utf-8')

    return aes_key_base64, private_key_header, final_body_base64



# --- 执行请求 ---

# 原始请求数据
payload = ''

# 生成加密数据
aes_key, rsa_header, encrypted_body = encrypt_request(payload)

headers = {
    "Host": "id.ustc.edu.cn",
    "sid-language": "zh_CN",
    "hasCrypto": "true",
    "origin": "https://id.ustc.edu.cn",
    "Referer": "填上你的 Referer",
    "privateKey": rsa_header,  # 这是 RSA 加密后的 AES 密钥
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
    # 记得带上你抓包到的 Cookie
    "Cookie": ""
}

response = requests.post(TARGET_URL, headers=headers, data=encrypted_body)

print(f"Status Code: {response.status_code}")
print(f"Encrypted Response: {response.text}")

# --- 解密响应 (如果需要) ---
if response.status_code == 200:
    try:
        encrypted_resp_raw = base64.b64decode(response.text)
        # 使用发送时的同一个 aes_key 进行解密
        cipher_decrypt = AES.new(base64.b64decode(aes_key), AES.MODE_ECB)
        decrypted_padded = cipher_decrypt.decrypt(encrypted_resp_raw)
        # 移除 Pkcs7 填充
        decrypted_text = decrypted_padded[:-decrypted_padded[-1]].decode('utf-8')
        print(f"Decrypted Data: {decrypted_text}")
    except Exception as e:
        print(f"解密失败或响应未加密: {e}")