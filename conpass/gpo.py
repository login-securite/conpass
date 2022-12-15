import re

from lsassy.impacketfile import ImpacketFile

class GPO:
    GPLINK_OPT_DISABLE = 1 << 0
    GPLINK_OPT_ENFORCE = 1 << 1

    def __init__(self, dn, options, lockout_threshold, lockout_reset):
        self.dn = dn
        self.options = options
        self.lockout_threshold = lockout_threshold
        self.lockout_reset = lockout_reset

    @staticmethod
    def get_password_policy(impacketfile, filepath):
        path = filepath.lower().split("sysvol")[1] + "\\Machine\\Microsoft\\Windows NT\\SecEdit"
        file = impacketfile.open(
            share="SYSVOL",
            path=path,
            file="GptTmpl.inf"
        )
        if file is None:
            return None, None
        content = file.read(file.size()).decode("utf-16-le")
        file.close()

        lockout_threshold = None if "LockoutBadCount" not in content else int(re.compile(r"LockoutBadCount *= *(\d+)").findall(content)[0])
        lockout_reset = None if "ResetLockoutCount" not in content else int(re.compile(r"ResetLockoutCount *= *(\d+)").findall(content)[0])

        if lockout_reset is None:
            lockout_reset = 0
        if lockout_threshold is None:
            lockout_threshold = 0

        return lockout_threshold, lockout_reset

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return f"GPO({self.dn}, {self.options}, {self.lockout_threshold}, {self.lockout_reset})"


