class PSO:
    def __init__(self, dn, lockout_threshold=None, lockout_window=None, lockout_duration=None, precedence=None, readable=True):
        self.dn = dn
        self.lockout_threshold = lockout_threshold
        self.lockout_window = lockout_window
        self.lockout_duration = lockout_duration
        self.precedence = precedence
        self.readable = readable

    def __str__(self):
        return f"Threshold: {self.lockout_threshold} - Window: {self.lockout_window} - Duration: {self.lockout_duration} - Precedence: {self.precedence}" if self.readable else "Access Denied"

    def __repr__(self):
        return self.__str__()