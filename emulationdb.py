import sqlite3
import zlib
import pickle
from argparse import Namespace


class EmulationDB:
    def __init__(self, filename="emulations.db"):
        self.filename = filename
        self.connection = sqlite3.connect(filename)
        self.connection.execute("CREATE TABLE IF NOT EXISTS emulations (id INTEGER PRIMARY KEY, elf_name VARCHAR, ckey VARCHAR, plaintext VARCHAR, ciphertext VARCHAR, mask VARCHAR, emulation_results_blob BLOB)")

    def add(self, elf_name, key, plaintext, ciphertext, mask, emulation_results):
        with self.connection:
            v = (elf_name, key, plaintext, ciphertext, mask, zlib.compress(pickle.dumps(emulation_results)))
            self.connection.execute("INSERT INTO emulations VALUES (NULL,?,?,?,?,?,?)", v)

    def get_all(self):
        with self.connection:
            cursor = self.connection.cursor()
            cursor.execute("SELECT elf_name, ckey, plaintext, ciphertext, mask, emulation_results_blob FROM emulations")
            for row in cursor:
                v = Namespace(elf_name=row[0],
                              key=row[1],
                              plaintext=row[2],
                              ciphertext=row[3],
                              mask=row[4],
                              emulation_results_blob=pickle.loads(zlib.decompress(row[5])))
                yield v
