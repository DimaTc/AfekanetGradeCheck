# AfekanetGradeCheck
A Simple script to login to AfekaNet and to check for new grades


## installation
```bash
git clone git@github.com:DimaTc/AfekanetGradeCheck.git
cd AfekanetGradeCheck
pip install -r requiremnts.txt
```

## Usage
To use the script you need to enter your credentials to Afeka and the details of an email address, that will be used to send the updates
```bash
python server.py
```

### Explanation 
You'll need to provide some details to the script, so it could send emails and check the site:

Enter Afeka's username: ***Your username***

Enter Afeka's password: ***Your password***

Enter SMTP address (smtp.gmail.com for Gmail)
Address: ***SMTP address of the email which will be used to send updates***

Enter SMTP port (587 for Gmail): ***The SMTP port***

Enter target mail address: ***The address which will be receiving the updates***

username(or email): ***Username of the SMTP server (or email for Gmail's SMTP)***

password (hidden): ***The password of the username above***

#now just write which year and semester you want to check

Please enter the academic year to listen to: ***Year*** [like 2020]

Please enter the semester to listen to:***Semester*** [like 1]

### IMPORTANT
***For the SMTP account, if you use Gmail, make sure to turn ON "Less secure app access"***
***in case that you have two-factor authentication, add an app password in the Gmail settings***
