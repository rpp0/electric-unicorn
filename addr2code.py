import subprocess
import pickle


class Addr2Code:
    def __init__(self, binary):
        self.binary = binary
        self.filename = ".addr2codecache-%s.p" % self.binary

        try:
            with open(self.filename, "rb") as f:
                self.cache = pickle.load(f)
        except FileNotFoundError:
            self.cache = {}

    def get_code(self, address: int):
        # If in cache, return it
        if address in self.cache:
            return self.cache[address]

        # Otherwise do lookup using addr2line
        hex_address = hex(address)
        out = subprocess.check_output(["addr2line", "-e", "./%s" % self.binary, hex_address])
        out = out.decode("utf-8").strip()
        path, line = out.split(":")

        # TODO hacky cracky hardcoded
        if 'hmac-sha1.c' in path:
            self.cache[address] = 'main'
        elif 'sha1-prf.c' in path:
            self.cache[address] = 'sha1_prf'
        elif 'sha1.c' in path:
            self.cache[address] = 'hmac_sha1_vector'
        elif 'sha1-internal.c' in path:
            self.cache[address] = 'sha1'
        else:
            self.cache[address] = None

        return self.cache[address]

    def __del__(self):
        with open(self.filename, "wb") as f:
            pickle.dump(self.cache, f)
