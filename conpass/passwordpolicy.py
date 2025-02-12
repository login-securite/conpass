class PasswordPolicy:
    def __init__(self, name, lockout_threshold=None, lockout_window=None):
        self.name = name
        self.lockout_threshold = lockout_threshold
        self.lockout_window = lockout_window

    def __str__(self):
        return f"Name: {self.name}, Lockout Threshold: {self.lockout_threshold} - Lockout Window: {self.lockout_window} seconds"

    def __repr__(self):
        return self.__str__()
