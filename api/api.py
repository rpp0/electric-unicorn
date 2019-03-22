from electricunicorn import ElectricUnicorn
from enum import IntEnum
from collections import namedtuple
from util import EUException

EUExperimentProperties = namedtuple("EUExperimentProperties", ["type", "path", "key_len", "plaintext_len"])


class EUExperimentType(IntEnum):
    HMAC_SHA1 = 0
    MEMCPY = 1


class EUExperiment:
    HMAC_SHA1 = EUExperimentProperties(type=EUExperimentType.HMAC_SHA1, path='./hmac-sha1', key_len=32, plaintext_len=76)
    MEMCPY = EUExperimentProperties(type=EUExperimentType.MEMCPY, path='./memcpy', key_len=128, plaintext_len=128)


def get_leakage(experiment: EUExperimentProperties, key: bytes, plaintext: bytes):
    e = ElectricUnicorn(experiment.path)

    if len(key) != experiment.key_len:
        raise EUException("Key length is invalid (expected %d but got %d)" % (experiment.key_len, len(key)))
    if len(plaintext) != experiment.plaintext_len:
        raise EUException("Plaintext length is invalid (expected %d but got %d)" % (experiment.plaintext_len, len(plaintext)))

    if experiment.type == EUExperimentType.HMAC_SHA1:
        return e.get_hmac_sha1_leakage_fast(pmk=key, data=plaintext)
    elif experiment.type == EUExperimentType.MEMCPY:
        return e.get_memcpy_leakage_fast(data=key, buffer=plaintext)
    else:
        raise EUException("Unknown experiment type %s" % str(experiment.type))
