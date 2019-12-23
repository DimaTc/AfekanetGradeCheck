import requests
import base64
import re
import threading
import time
from mail_server import MailServer
from random import randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from requests import Session
from getpass import getpass
from bs4 import BeautifulSoup
headers = {
    'user-agent': 'Google Chrome Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36.'}

main_url = "https://yedion.afeka.ac.il/yedion/fireflyweb.aspx"

updated_grades = {}

GRADE_CHECK_DELAY = 60 * 2  # delay for the check grade thread
MAIL_SEND_DELAY = 15


AFEKA_USERNAME = 0
AFEKA_PASSWORD = 1
SMTP_ADDRESS = 2
SMTP_PORT = 3
SMTP_USERNAME = 4
SMTP_PASSWORD = 5
MAIL_TARGET = 6
TOTAL = 7

error = False


def get_user_params():
    username = input("Enter Afeka's username:")
    password = getpass("Enter Afeka's password:")
    return (username, password)


def start_server():
    print("Starting Server...")
    #### get the login data and save it ####
    data = load_settings()
    grades = read_grades()
    login_failed = True
    first_time = True
    while login_failed:
        if not grades:
            grades = {}
            print("No saved file found, starting from zero")
        if data:
            username, password = data[0:2]
            smtp_data = data[2:]
        else:
            username, password = get_user_params()
            if first_time:
                smtp_data = get_smtp_params()
                first_time = False
        #######################################
        try:
            session = get_logged_in_session(username, password)
            login_failed = False
        except:
            print("Login Error, Check username/password")
    print("Successfully logged in")
    tmp = [username, password]
    tmp.extend(smtp_data)
    save_settings(tmp)
    print("config file saved in\n")

    flag = True
    year = 2020  # default values - will be replaces
    semester = 1
    while(flag):
        year = input("Please enter the academic year to listen to:")
        semester = input("Please enter the semester to listen to:")
        try:
            year = int(year)
            semester = int(semester)
            flag = False
        except Exception as e:
            print(e)
            print("Invalid values!")
    print("Starting checking on grades for year - {}, semster - {}".format(year, semester))
    grade_thread = threading.Thread(target=check_grades, args=[
                                    session, year, semester, grades, username, password], daemon=True)
    grade_thread.start()

    smtp_server = MailServer(smtp_data[SMTP_USERNAME - 2], smtp_data[SMTP_PASSWORD - 2],
                             smtp_data[SMTP_ADDRESS - 2], smtp_data[SMTP_PORT - 2])
    smtp_server.set_target(smtp_data[MAIL_TARGET - 2])
    while not error:
        time.sleep(MAIL_SEND_DELAY)
        check_for_updates(smtp_server)


def check_for_updates(smtp_server: MailServer):
    global updated_grades
    if len(updated_grades) > 0:
        body = "Subject: New Grades!\n"
        body += "Content-Type: text/html; charset=\"UTF-8\"\n\n"
        body += "<div dir=\"rtl\">\n"
        for k in updated_grades:
            body += "<b>{}:</b> {}\n".format(k, updated_grades[k])
            print("\nNew Grade:{} == {}\n<br>".format(k, updated_grades[k]))
        body += "</div>\n"
        updated_grades = {}  # reset
        smtp_server.sendMessage(body)


def check_grades(session, year, semester, last_grades, username, password):
    try:
        print("Listening for changes...")
        first_run = True
        kept_alive = True
        while(True):
            print(time.ctime(time.time()),end=": ")
            grade_page = get_grade_page(main_url, session, year, semester)
            if not grade_page or not kept_alive:
                try:
                    print("Authentication error - trying to re-login")
                    session.close()
                    session = get_logged_in_session(username, password)
                    continue
                except Exception as e:
                    print("Relogin didn't go well - try to restart the server ")
                    raise e
            grades = get_grades(grade_page)
            diff_grades = get_diff_grades(last_grades, grades)
            if len(diff_grades) > 0 and not first_run:
                print("New grades!")
                global updated_grades
                updated_grades = diff_grades
            first_run = False
            for k in diff_grades:
                last_grades[k] = diff_grades[k]

            save_grades(last_grades)
            time.sleep(GRADE_CHECK_DELAY)  # sleep for 5 minutes
            kept_alive = keep_alive(session)
    except Exception as e:
        print(e)
        global error
        error = True


def keep_alive(session: Session):
    try:
        url = "https://yedion.afeka.ac.il/yedion/fireflyweb.aspx?prgname=StayConnect"
        session.post(url,headers=headers)
    except Exception as e:
        print(e)
        return False
    return True

def get_diff_grades(old, new):
    diff = {}
    flag = True
    for k in new:
        try:
            flag = True
            if old[k] == new[k]:  # same grade without change
                flag = False
        except:
            flag = True
        finally:
            #changed or new
            if flag:
                diff[k] = new[k]
    return diff


def load_settings():
    try:
        with open("data", "rb") as f:
            data = f.read()
            line = base64.decodebytes(data).decode().strip()
            data = line.split("\n")
            if len(data) != TOTAL:
                print("settings file corrupted, enter the data manually")
                return None
            return data
    except IOError:
        print("No settings file was found")
        return None

def save_settings(data):
    data_b = ""
    with open("data", 'wb') as f:
        for line in data:
            data_b += "\n" + line
        data_b = data_b.encode()
        f.write(base64.encodebytes(data_b))


def save_grades(grades):
    with open("grades.txt", "wb") as f:
        for sub in grades:
            line = "{}={}\n".format(sub, grades[sub])
            f.write(line.encode())


def read_grades():
    raw_grade = {}
    try:
        with open("grades.txt", 'rb') as f:
            for _, line in enumerate(f):
                line = line.decode()
                line = line.replace("\n", "")
                try:
                    sub, grade = line.split("=")
                    try:
                        grade = int(grade)
                    except:
                        pass
                    raw_grade[sub] = grade
                except:
                    print("{} - not in the right format, skipping...".format(line))
    except IOError:
        return None
    return raw_grade


def get_logged_in_session(username, password):
    session = requests.session()
    res = None
    try:
        res = session.get(main_url)
    except Exception as e:
        session.close()
        print(e)
        print("Closing program...")
        return None
    # session.cookies.clear()
    current_url = res.url
    print("Got respone from - ", current_url)
    login(username, password, url=current_url, session=session)

    return session


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
    grades = {}
    for row in rows:

        raw_subject = ''.join(row.findChildren("td")[1].contents)
        raw_subject = raw_subject.replace("\xa0", " ")
        raw_subject = raw_subject.replace("\t", "")
        raw_subject = raw_subject.replace("\r\n", "")
        raw_subject = re.sub(r'\d+', "", raw_subject).strip()
        subject_type = (''.join(row.findChildren("td")[2])).strip()
        raw_grade = (''.join(row.findChildren("td")[5].contents)).replace(
            "\xa0", "").strip()
        try:
            raw_grade = int(raw_grade)
        except:
            pass
        val = "{}({})".format(raw_subject, subject_type)
        grades[val] = raw_grade
    return grades


def afeka_login_key(session: Session):
    url = "https://yedion.afeka.ac.il/yedion/FireflyWeb.aspx?PRGNAME=Enc"
    res = session.post(url, headers)
    enc_key = res.content
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
    try:
        res = session.post(url, headers=headers, data=params1)
        soup = BeautifulSoup(res.content, 'html.parser')
        e_tz = soup.find(attrs={'name': 'TZ'})
        e_uniq = soup.find(attrs={'name': 'UNIQ'})
        tz = ""
        uniq = ""
        tz = e_tz['value']
        uniq = e_uniq['value']
        params2["TZ"] = tz
        params2["UNIQ"] = uniq
        params2["R1C1"] = year
        params2["R1C2"] = semester
        print("Got UNIQ and TZ - {} , {}".format(uniq, tz))
        res = session.post(main_url, data=params2, headers=headers)
    except Exception as e:
            print(e)
            print("There was a problem getting the grade page")
            return None

    return res


def get_smtp_params():
    print("\nSetting up the smtp server...")
    print("Enter smtp address (smtp.gmail.com for gmail)")
    smtp = input("Address:")
    port = input("Enter smtp port (587 for gmail):")
    target = input("Enter target mail address:")
    print("Enter from which mail the data will be sent")
    username = input("username(or email):")
    print("Enter the password for that username")
    password = getpass("password (hidden):")

    return [smtp, port, username, password, target]


if __name__ == "__main__":
    start_server()
