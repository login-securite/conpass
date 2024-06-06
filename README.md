# ConPass

[![PyPI version](https://badge.fury.io/py/conpass.svg)](https://pypi.org/project/conpass)
[![PyPI Statistics](https://img.shields.io/pypi/dm/conpass.svg)](https://pypistats.org/packages/conpass)
[![Twitter](https://img.shields.io/twitter/follow/hackanddo?label=HackAndDo&style=social)](https://twitter.com/intent/follow?screen_name=hackanddo)

Python tool for continuous password spraying taking into account the password policy.

Associated blogposts
* English: https://en.hackndo.com/password-spraying-lockout/
* French: https://www.login-securite.com/2024/06/03/spray-passwords-avoid-lockouts/

| Chapters                                | Description                                     |
|-----------------------------------------|-------------------------------------------------|
| [Warning](#warning)                     | Before using this tool, read this               |
| [Installation](#installation)           | ConPass installation                             |
| [Usage](#usage)                         | ConPass usage                                   |

## Warning

Although I have made every effort to make sure the tool get the correct password policy, there can be some password policy settings that are not taken into account by the tool, which may lead to accounts lockout.

## Installation

**conpass** works with python >= 3.7

### pip (Recommended)

```bash
python -m pip install conpass
```

### From source for development

```
python setup.py install
```

## Usage

**conpass** will get all domain users and try a list of password provided in a password file. When a user can be locked out, the tool will wait for the lockout reset period before trying another password.

```bash
conpass -d domain -u pixis -p P4ssw0rd -P /tmp/passwords.txt
```

All passwords and NT hashes provided in `/tmp/passwords.txt` will be added to a testing Queue, and will be tested against all users, whenever it is possible without locking users out.
