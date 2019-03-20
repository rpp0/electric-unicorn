import sqlite3
import zlib


class EmulationDB:
    def __init__(self, filename="emulations.db"):
        self.filename = filename
        self.connection = sqlite3.connect(filename)
        self.connection.execute("CREATE TABLE IF NOT EXISTS emulations (id INTEGER PRIMARY KEY, elf_name VARCHAR, ckey VARCHAR, plaintext VARCHAR, ciphertext VARCHAR, mask VARCHAR, emulation_results_blob BLOB)")

    def add(self, elf_name, key, plaintext, ciphertext, mask, emulation_results_blob):
        with self.connection:
            v = (elf_name, key, plaintext, ciphertext, mask, zlib.compress(emulation_results_blob))
            self.connection.execute("INSERT INTO emulations VALUES (NULL,?,?,?,?,?,?)", v)

    def get_all(self):
        with self.connection:
            cursor = self.connection.cursor()
            cursor.execute("SELECT * FROM emulations")
            for row in cursor:
                v = (row[1], row[2], row[3], row[4], row[5], zlib.decompress(row[6]))
                yield v
