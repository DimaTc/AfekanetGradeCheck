import smtplib


class MailServer:
    """ Simple SMTP server for sending a SIMPLE mail"""

    def __init__(self, username, password, smtp, port):
        self.username = username
        self.password = password
        self.smtp = smtp
        self.port = port

    def set_target(self, target):
        self.target = target

    def setupServer(self):
        s = smtplib.SMTP(host=self.smtp, port=self.port)
        s.starttls()
        s.login(self.username, self.password)
        return s

    def sendMessage(self, message):
        print("Setting up server...")
        self.srv = self.setupServer()
        print("Sending mail...")
        self.srv.sendmail(self.username, self.target,
                          message.encode(encoding="utf-8"))
        # print("Mail sent! to {}".format(self.target))
