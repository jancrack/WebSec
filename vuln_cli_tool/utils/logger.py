#class Logger:
 #   pass
class Logger:
    def __init__(self, verbose=True):
        self.verbose = verbose

    def log(self, message):
        if self.verbose:
            print(f"[+] {message}")
