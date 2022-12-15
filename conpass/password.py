import re
from enum import Enum


class PASSWD_TYPE(Enum):
    PLAIN = 0
    NT = 1


class Password:
    def __init__(self, value):
        self.value = value
        self.type = self.get_type()

    def get_type(self):
        pattern = re.compile("^(?:[A-Fa-f0-9]{32}:)?[A-Fa-f0-9]{32}$")
        if pattern.match(self.value):
            if ':' in self.value:
                self.value = self.value.split(':')[1]
            return PASSWD_TYPE.NT
        return PASSWD_TYPE.PLAIN

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.value == other.value and self.type == other.type