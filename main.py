import requests
from bs4 import BeautifulSoup
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ================= 配置区 =================
USER_NAME = "SA23221114"
PASSWORD = "**********"
BASE_URL = "https://id.ustc.edu.cn/cas/login?service=https%3A%2F%2Fxn.face.ustc.edu.cn%2Fbio%2Fvalidate%2Ftoken"
DEVICE_COOKIES = {
    "device": "",
    "deviceID": ""
}
RISK_TOKEN = ""


# ==========================================

def aes_encrypt(key_base64, plain_text):
    key = base64.b64decode(key_base64)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(plain_text.encode('utf-8'), AES.block_size, style='pkcs7')
    return base64.b64encode(cipher.encrypt(padded_data)).decode('utf-8')


def start_login():
    session = requests.Session()
    # 初始注入指纹
    for k, v in DEVICE_COOKIES.items():
        session.cookies.set(k, v, domain="id.ustc.edu.cn")

    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document"
    })

    # 1. 获取登录页参数
    res = session.get(BASE_URL)
    soup = BeautifulSoup(res.text, 'html.parser')
    c_key = soup.find(id="login-croypto").get_text(strip=True)
    execution = soup.find(id="login-page-flowkey").get_text(strip=True)

    # 2. 加密
    pass_enc = aes_encrypt(c_key, PASSWORD.strip())
    risk_enc = aes_encrypt(c_key, json.dumps({"token": RISK_TOKEN, "groupId": ""}, separators=(',', ':')))
    cap_enc = aes_encrypt(c_key, "{}")

    # 3. 提交认证表单
    post_data = {
        "username": USER_NAME, "type": "UsernamePassword", "_eventId": "submit",
        "execution": execution, "croypto": c_key, "password": pass_enc,
        "captcha_payload": cap_enc, "risk_payload": risk_enc,
        "targetSystem": "sso", "siteId": "sourceId", "riskEngine": "true"
    }

    print("[*] 正在提交 CAS 认证...")
    r = session.post("https://id.ustc.edu.cn/cas/login", data=post_data, allow_redirects=False)

    # --- 循环处理 4 次跳转 ---
    # 按照你的报文：
    # Hop 1: https://id.ustc.edu.cn/cas/oauth2.0/callbackAuthorize?ticket=ST...
    # Hop 2: https://id.ustc.edu.cn/cas/oauth2.0/authorize?client_id=...
    # Hop 3: https://id.ustc.edu.cn/gate/login?code=OC...
    # Hop 4: http://id.ustc.edu.cn/gate/cas-success/personal-center-home-page...

    count = 1
    while r.status_code == 302:
        loc = r.headers.get("Location")
        if not loc: break

        # 补全 URL
        if loc.startswith("/"):
            loc = "https://id.ustc.edu.cn" + loc

        print(f"[*] 跳转 {count}: {loc}")

        # 更新 Referer 为当前请求的 URL
        session.headers.update({"Referer": r.url})

        # 处理 Gate 系统的 SESSION 覆盖和路径问题
        if "SESSION" in r.cookies:
            val = r.cookies.get("SESSION")
            # 强制为 /gate/ 路径设置 Cookie，防止后续请求丢失
            session.cookies.set("SESSION", val, domain="id.ustc.edu.cn", path="/gate/")
            print(f"    [Cookie同步] 已获取新 SESSION: {val[:8]}...")

        # 执行 GET
        r = session.get(loc, allow_redirects=False)
        count += 1
        if count > 10: break  # 安全限制

    # 4. 最终状态判定
    final_url = r.url
    print(f"\n[*] 最终到达: {final_url}")

    final_res = session.get(final_url)

    print("\n=== [Response Headers] ===")
    for key, value in final_res.headers.items():
        print(f"{key}: {value}")
    print("\n=== [Response Body] ===")
    print(final_res.text)

    # 打印请求头 (Request Headers)
    # 这能让你确认 Python 到底带了哪些 Cookie 发给服务器
    print("\n=== [Request Headers] ===")
    for key, value in final_res.request.headers.items():
        print(f"{key}: {value}")

    # 5. 访问具体的业务接口 (staffInfoV2)
    print("\n[*] 正在请求 staffInfoV2 接口...")
    api_url = "https://xn.face.ustc.edu.cn/bio/api/selfcollect/getInfo"

    # 根据你的描述，Payload 是 JSON 格式
    api_payload = {"xh": ""}

    # 更新 Header 模拟真实的 AJAX 请求
    session.headers.update({
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "https://xn.face.ustc.edu.cn",
        "Referer": "https://xn.face.ustc.edu.cn/bio/",  # 这里的 Referer 根据实际页面调整
        "X-Requested-With": "XMLHttpRequest"
    })

    try:
        # 发送 POST 请求
        api_res = session.post(api_url, json=api_payload)

        print("\n=== [API Response Headers] ===")
        # 使用 json.dumps 优雅打印 Header
        print(json.dumps(dict(api_res.headers), indent=4))

        print("\n=== [API Response Body] ===")
        # 尝试以 JSON 格式优雅打印返回结果
        try:
            print(json.dumps(api_res.json(), indent=4, ensure_ascii=False))
        except:
            print(api_res.text)  # 如果不是 JSON 则打印原文

    except Exception as e:
        print(f"❌ 请求接口失败: {str(e)}")


if __name__ == "__main__":
    start_login()