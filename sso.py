import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
import base64

url = "https://sso.qlu.edu.cn/login?service=https:%2F%2Fjw.qlu.edu.cn%2Fsso%2Fddlogin"
password = ""
# AES 加密函数
def aes_encrypt(key, data):
    key = base64.b64decode(key)
    cipher = AES.new(key, AES.MODE_ECB)
    pad = 16 - len(data) % 16
    data = (data + chr(pad) * pad).encode('utf-8')
    encrypted = cipher.encrypt(data)
    return base64.b64encode(encrypted).decode('utf-8')

# 提取 JSESSIONID 和 route
def get_JSESSIONID_route(header):
    set_cookie = header.get('Set-Cookie', '')
    cookies = {}
    for item in set_cookie.split(', '):
        parts = item.split(';')[0]
        if '=' in parts:
            key, value = parts.split('=', 1)
            cookies[key] = value
    JSESSIONID = cookies.get('JSESSIONID')
    route = cookies.get('route')
    return JSESSIONID,route
# 主函数
def main(url,password):
    # 获取 execution 和 croypto
    session = requests.Session()
    response = session.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    execution = soup.find("p", {"id": "login-page-flowkey"}).text
    croypto = soup.find("p", {"id": "login-croypto"}).text
    # 登录信息
    username = ""
    password_plain = password
    password_encrypted = aes_encrypt(croypto, password_plain)  # 使用 croypto 作为 AES 密钥
    # 构造请求数据
    data = {
        "username": username,
        "type": "UsernamePassword",
        "_eventId": "submit",
        "geolocation": "",
        "execution": execution,
        "captcha_code": "",
        "croypto": croypto,
        "password": password_encrypted
    }
    # 发送请求
    #第一次返回ticket
    req1 = session.post(url, data=data, allow_redirects=False)
    #第二次返回route
    url2 = req1.headers.get("Location")
    #print(url2)
    req2 = session.get(url2, allow_redirects=False)
    #print(req2.headers)
    #第三次返回https://jw.qlu.edu.cn/jwglxt/ticketlogin?uid=202285050045&timestamp=1732594319&verify=F59FB15F844535FAEA8212B35F3492B2
    url3 = "https://jw.qlu.edu.cn/sso/ddlogin"
    req3 = session.get(url3, allow_redirects=False)
    #print(req3.headers)
    #第四次更新route,JSESSIONID
    url4 = req3.headers.get("Location")
    req4 = session.get(url4, allow_redirects=False)
    head = req4.headers
    JSESSIONID,route = get_JSESSIONID_route(head)
    with open("/usr/Tools/QLU/Cookie.txt", 'w') as f:
        # 模拟常见的cookie文件格式，每一行一个cookie，key=value
        f.write(f'JSESSIONID={JSESSIONID};route={route}\n')
if __name__ == "__main__":
    main(url,password)