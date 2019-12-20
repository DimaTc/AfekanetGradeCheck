import requests
import base64
# from Crypto.Cipher import AES
from Crypto.Cipher import AES
from requests import Session
from getpass import getpass
from lxml import html

headers = {
    'user-agent': 'Google Chrome Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36.'}


def get_user_params():
    username = input("Enter username:")
    password = getpass("Enter password:")
    # password = input("Enter password:")
    return (username, password)


def start_server():
    print("Starting Server...")
    username, password = get_user_params()

    session = requests.session()
    res = None
    try:
        res = session.get(
            "https://yedion.afeka.ac.il/yedion/fireflyweb.aspx")
    except Exception as e:
        session.close()
        print(e)
        print("Closing program...")
        return
    session.cookies.clear()
    current_url = res.url
    print("Got respone from - ", current_url)
    cookies = get_cookies(res)
    update_cookies(session, cookies)
    login(username, password, url=current_url, session=session)


def login(username, password, url, session: Session):
    data = {
        'username': username,
        'password': password,
        'Domain': 'ACADEMIC',
        'vhost': 'standard'
    }

    session.max_redirects = 50
    res = session.post(url, data=data, headers=headers, allow_redirects=False)
    url = res.headers['location']

    # print(res.headers)
    update_cookies(session, get_cookies(res))
    key = afeka_login_key(session)
    res = session.get(url, headers=headers)
    print(key)
    content = res.content
    with open("page.html", 'w', encoding='cp1255') as file:
        file.write(content.decode('utf-8'))


def afeka_login_key(session: Session):
    url = "https://yedion.afeka.ac.il/yedion/FireflyWeb.aspx?PRGNAME=Enc"
    res = session.post(url, headers)
    enc_key = res.content
    key = base64.decodestring(enc_key).decode()
    print(key, enc_key)
    return key


def update_cookies(session, cookies):
    for cookie in cookies:
        session.cookies[cookie] = cookies[cookie]


def get_cookies(res):
    cookies = {}
    raw_cookies = res.headers['Set-Cookie'].split(',')
    for cookie_raw in raw_cookies:
        cookie_raw = cookie_raw.replace("secure", "")
        cookie_raw = cookie_raw.split(";")[0]
        cookie_raw = cookie_raw.strip()
        try:
            (header, value) = cookie_raw.split("=")
            cookies[header] = value
        except:
            print("Error reading the cookie - ", cookie_raw)
    return cookies


if __name__ == "__main__":
    start_server()
