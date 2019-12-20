import requests
import base64
# DEBUG
import logging
import http.client as http_client
#
from random import randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from requests import Session
from getpass import getpass
from bs4 import BeautifulSoup
headers = {
    'user-agent': 'Google Chrome Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36.'}

main_url = "https://yedion.afeka.ac.il/yedion/fireflyweb.aspx"

# DEBUG STUFF
# http_client.HTTPConnection.debuglevel = 1
# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)

# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True
#


def get_user_params():
    username = input("Enter username:")
    password = getpass("Enter password:")
    return (username, password)


def start_server():

    print("Starting Server...")
    username, password = get_user_params()

    session = requests.session()
    res = None
    try:
        res = session.get(main_url)
    except Exception as e:
        session.close()
        print(e)
        print("Closing program...")
        return
    # session.cookies.clear()
    current_url = res.url
    print("Got respone from - ", current_url)
    login(username, password, url=current_url, session=session)
    login_cookie = {
        "name": 'LogedIntoYedion',
        "value": 'Yes',
        "path": 'afeka.ac.il',
        "domain": 'yedion.'
    }
    session.cookies.set(**login_cookie)

    # TODO: check if logged in
    grade_page = get_grade_page(main_url, session,2020,1)
    grades = get_grades(grade_page)


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
    # get login key and encrypt password
    key = afeka_login_key(session)
    enc_password = get_encrypted_password(password, key)
    req_data = format_login_request(username, enc_password)
    ####

    tmp = requests.Request("POST", main_url, files=req_data, headers=headers)
    tmp = session.prepare_request(tmp)
    res = session.send(tmp)


def get_grades(grade_page):
    page = BeautifulSoup(grade_page.content, 'html.parser')
    grade_table = page.find(id="myTable0")
    grade_table = grade_table.findChild("tbody")
    rows = grade_table.findChildren("tr")
    grades = [''.join(row.findChildren("td")[5].contents).replace("\xa0","") for row in rows]
    for row in rows:
        a = ''.join(['a','b'])
        raw_subject = (''.join(row.findChildren("td")[1].contents)).replace("\xa0","")
        raw_grade = (''.join(row.findChildren("td")[5].contents)).replace("\xa0","")


    print(grades)
    return False


def afeka_login_key(session: Session):
    url = "https://yedion.afeka.ac.il/yedion/FireflyWeb.aspx?PRGNAME=Enc"
    res = session.post(url, headers)
    enc_key = res.content
    print(enc_key)
    key = base64.decodestring(enc_key)
    print("Got key - ", key.decode())
    return key


def get_encrypted_password(pw, key):
    pw = pw.encode("utf-8")
    aes = AES.new(key, iv=key, mode=AES.MODE_CBC)
    pw = pad(pw, 16)
    enc = aes.encrypt(pw)
    return base64.encodebytes(enc).decode().strip()


def format_login_request(username, password):
    req_data = {}
    content = [
        ("PRGNAME", "LoginValidation"),
        ("R1C5", password),
        ("generatedToken", "0"),
        ("ARGUMENTS", "R1C1,R1C2,-AH,-A,-N,-N,-N,-A,R1C5"),
        ("R1C1", username),
        ("R1C2", "")
    ]
    for param, value in content:
        req_data[param] = (None, value)

    return req_data


def get_grade_page(url, session: Session, year, semester):
    params1 = {"prgname": "MenuCall",
               "arguments": "-N%2C-N%2C-N13%2C-AH"}  # for the first page
    params2 = {
        "APPNAME": "", 
        "PRGNAME": "Bitsua_maarechet_shaot",
        "ARGUMENTS": "TZ%2CUNIQ%2CMisparSheilta%2CR1C1%2CR1C2",
        "MisparSheilta": "13",
    }
    res = session.post(url, headers=headers, data=params1)
    soup = BeautifulSoup(res.content, 'html.parser')
    e_tz = soup.find(attrs={'name': 'TZ'})
    e_uniq = soup.find(attrs={'name': 'UNIQ'})
    tz = ""
    uniq = ""
    try:
        tz = e_tz['value']
        uniq = e_uniq['value']
    except:
        print("There was a problem getting to the grade page")
        return False
    params2["TZ"] = tz
    params2["UNIQ"] = uniq
    params2["R1C1"] = year
    params2["R1C2"] = semester
    print("Got UNIQ and TZ - {} , {}".format(uniq, tz))
    res = session.post(main_url,data=params2, headers=headers)

    return res

def update_cookies(session, cookies):  # TODO: Check if it can be removed (and get_cookies)
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
