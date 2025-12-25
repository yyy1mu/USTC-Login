import requests
from bs4 import BeautifulSoup
import base64
import json
import time
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from urllib.parse import urlparse, urljoin

# ================= 配置区 =================
USER_NAME = "SA23221114"
PASSWORD = "---------"
# 目标业务系统的初始入口 URL
BASE_URL = "https://id.ustc.edu.cn/cas/login?service=https:%2F%2Fid.ustc.edu.cn%2Fcas%2Foauth2.0%2FcallbackAuthorize%3Fclient_id%3DOC4wNS4wNS4wNy4wMC4wMy4wMS4wMS4w%26redirect_uri%3Dhttps%253A%252F%252Fid.ustc.edu.cn%252Fgate%252Flogin%26response_type%3Dcode%26client_name%3DCasOAuthClient&state=LmoJjS&client_id=OC4wNS4wNS4wNy4wMC4wMy4wMS4wMS4w"
CONFIG_FILE = "device_info.json"


# ==========================================

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def aes_encrypt(key_base64, plain_text):
    key = base64.b64decode(key_base64)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(plain_text.encode('utf-8'), AES.block_size, style='pkcs7')
    return base64.b64encode(cipher.encrypt(padded_data)).decode('utf-8')


def load_or_generate_device():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    print("[!] 正在初始化新设备指纹...")
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
    # 默认UA是windows系统，风险引擎对于UA的校验比较严格
    # todo : TOTP加入受信任的设备
    # 修改头之后需要您删除本地的 device_info.json 文件以重新生成指纹
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    config = {
        "device": sha256_hex(str(int(time.time() * 1000))),
        "deviceID": sha256_hex(f"{ua}|MacIntel|zh-CN|8-core"),
        "userAgent": ua,
        "riskSystemGroupId": ""
    }
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)
    return config


def get_risk_token(device_info):
    print("[*] 正在向 analytics 获取风控令牌...")
    components = {
        'fonts': ["Arial", "Courier New"], 'deviceMemory': 8, 'hardwareConcurrency': 8,
        'timezone': "Asia/Shanghai", 'cpuClass': "unknown", 'platform': "MacIntel",
        'language': "zh-CN", 'screenResolution': [1920, 1080]
    }
    keys_order = ['fonts', 'deviceMemory', 'hardwareConcurrency', 'timezone', 'cpuClass', 'platform', 'language',
                  'screenResolution']
    concat_str = ""
    hash_map = {}
    for k in keys_order:
        val_json = json.dumps(components[k], separators=(',', ':'))
        hash_map[k] = val_json
        concat_str += val_json
    payload = {
        "fonts": sha256_hex(hash_map['fonts']),
        "deviceMemory": sha256_hex(hash_map['deviceMemory']),
        "hardwareConcurrency": sha256_hex(hash_map['hardwareConcurrency']),
        "localgroupId": device_info["riskSystemGroupId"],
        "timezone": hash_map['timezone'],
        "cpuClass": sha256_hex(hash_map['cpuClass']),
        "platform": hash_map['platform'],
        "language": hash_map['language'],
        "screenResolution": hash_map['screenResolution'],
        "fingerprint": sha256_hex(concat_str),
        "cookieValue": device_info["device"],
        "userAgent": device_info["userAgent"],
        "platformAuthenticator": "nonsupport"
    }
    try:
        res = requests.post("https://analytics.ustc.edu.cn/fp", json=payload, timeout=5)
        return res.json().get("responsetoken")
    except:
        return None


def start_login():
    device_info = load_or_generate_device()
    risk_token = get_risk_token(device_info) or "error_fallback"

    session = requests.Session()
    session.headers.update({"User-Agent": device_info["userAgent"]})

    # 初始指纹 Cookies
    session.cookies.set("device", device_info["device"], domain="ustc.edu.cn")
    session.cookies.set("deviceID", device_info["deviceID"], domain="id.ustc.edu.cn")

    # 1. 获取登录页参数
    print(f"[*] 访问 CAS 登录页...")
    res = session.get(BASE_URL)
    soup = BeautifulSoup(res.text, 'html.parser')
    c_key = soup.find(id="login-croypto").get_text(strip=True)
    execution = soup.find(id="login-page-flowkey").get_text(strip=True)

    # 2. 构造加密 Payload
    pass_enc = aes_encrypt(c_key, PASSWORD.strip())
    risk_data = {"token": risk_token, "groupId": device_info["riskSystemGroupId"]}
    risk_enc = aes_encrypt(c_key, json.dumps(risk_data, separators=(',', ':')))
    cap_enc = aes_encrypt(c_key, "{}")

    post_data = {
        "username": USER_NAME, "type": "UsernamePassword", "_eventId": "submit",
        "execution": execution, "croypto": c_key, "password": pass_enc,
        "captcha_payload": cap_enc, "risk_payload": risk_enc,
        "targetSystem": "sso", "siteId": "sourceId", "riskEngine": "true"
    }

    # 3. 提交登录并处理 302 重定向链
    print("[*] 提交认证并开始跳转...")
    r = session.post("https://id.ustc.edu.cn/cas/login", data=post_data, allow_redirects=False)

    hop_count = 0
    while r.status_code == 302:
        hop_count += 1
        loc = r.headers.get("Location")
        if not loc: break

        # 智能拼接 URL (处理相对路径和跨域名)
        loc = urljoin(r.url, loc)

        print(f"[*] 跳转 {hop_count}: {loc[:70]}...")

        # 核心：更新 Referer
        session.headers.update({"Referer": r.url})

        # 处理 Gate 系统的特殊 SESSION
        if "SESSION" in r.cookies:
            val = r.cookies.get("SESSION")
            # 兼容 Gate 系统的路径 Cookie 策略
            session.cookies.set("SESSION", val, domain="id.ustc.edu.cn", path="/gate/")

        # 执行跳转
        r = session.get(loc, allow_redirects=False)
        if hop_count > 12: break  # 安全退出

    # 4. 最终业务请求
    print(f"\n[+] 认证链完成，最终地址: {r.url}")

    print("\n=== [Response Headers] ===")
    for key, value in r.headers.items():
        print(f"{key}: {value}")
    print("\n=== [Response Body] ===")
    # print(final_res.text)

    # 打印请求头 (Request Headers)
    # 这能让你确认 Python 到底带了哪些 Cookie 发给服务器
    print("\n=== [Request Headers] ===")
    for key, value in r.request.headers.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    start_login()