import base64
from Crypto.Cipher import AES
from Crypto.Util import Counter


KEY = bytes([
    45,  67,  89,  12,
    34,  56,  78,  90,
    123, 234, 45,  67,
    89,  12,  34,  56,
])


PAYLOAD_PREFIX = b"\x01a\x01\x001"


def fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h



def derive_iv(timestamp: int, nonce: int) -> bytes:
    r67 = "0" + str(timestamp)
    iv = b""
    for i in range(4):
        h = fnv1a32((r67 + str(i) + str(nonce)).encode())
        if h & 0x80000000:
            h = 0x100000000 - h
        iv += h.to_bytes(4, "big")
    return iv


def _cipher(iv: bytes):
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    return AES.new(KEY, AES.MODE_CTR, counter=ctr)


def encrypt(data: bytes, timestamp: int, nonce: int) -> str:
    iv = derive_iv(timestamp, nonce)
    return base64.b64encode(iv + _cipher(iv).encrypt(data)).decode()


def decrypt(blob: str) -> bytes:
    raw = base64.b64decode(blob)
    for off in range(len(raw) - 16):
        iv = raw[off:off + 16]
        ct = raw[off + 16:]
        pt = _cipher(iv).decrypt(ct)
        if pt.startswith(PAYLOAD_PREFIX):
            return pt
    raise ValueError("no IV offset found (decrypted payload prefix mismatch)")


if __name__ == "__main__":
    blob = "AzQABAC6AAFQkc8TtpPVMpiDARfSdN8qgOlqdA5a9PA7rCfSvE7LBL/eRK47YPMkA46tCCabjdbACmrGtjTVqHR1LPQ/7ldz/tshIhJTHCt4a6CW4/2R+JGXIb3ub9GFPuvwcXn1ekrADt4phd5bmgVIZaNvmMk1+iKKqDz1LEnyyfY26+KAliNo/+/jx6Ii/2eAA8bkl/gX+Q2jzxL4gmC3KSZdHAfy8RAmihkM3FtX76DJMW9PpeMMU+14UUbFTJ/PDCgJjnd4kpO6abr6IZMhcTd0YWEedep5ifEkPmzkE46W0DLgvpimHnV3yhPfpQY2RxXL9kdiacVKl8N7XQxjWCFbtzZWzFOidq5ax3iKHfxzR7reoLlTE2CycXRFrbHQcZkXzrG6J3O6NFmw5KYeuhOgzCMObdrsDNwepD9t4VE++5q7bl0rXUhsdRC7Dz0RoP+LOkrkm6yLId+h+JvPtxHA3Ftq0nZ7quylYJmD0jgpu2IER0JeITo/mZSlnLO4JoMCCIkvJZcBYwXZi03fzfgy/ud08F4q84rDgXDtb+Nred82Liry4zOM16g1aI44xddGriXpyUSd1twNRfjnU1SP38Go2Qecr2jxfWzlCxYPaTcmLzxq1f/kTIxGhebiMjdQwF+/Dj4gcXHBNrG9Tz2s1SGFC3+FhkYjiWyWjbMZ/mbUE5Fr/5buFyd+Jntq5hjCs2QnnB2YR4x4VnY27egr+snjnlpHCgPURBvDqUOIOLhRz/O5nGT5DHiNkFOFKHPjE1SKRjDjvK5VUlqZS3w9gfdTuPrQBSFkkc+wj6be7Y/NQ7q6diqZtUZUz/EujQIjrB3Su+H08y1anKtDMThQEIED/n2fmcpp2TOOQtH29kkwOrQubIVRDLZ83ea2f189yxYKXZ0Wi8NGO/s18yonbAkacTWRNh8SBJOzUSAM09kqLlrQ4euDM2KupQeRLLWwepsU1YTYSdgJghVRrgyXl/jL+l/obRzkpgWZIKcFIypRcHg3ffVoMp5guFFeoIWBIr3WtrG0zO82/ibnK5+BEsjNIt2xXRhjrxk3T414YeWEsPnDW5Z7U1vf7J1skOJPjmkav83OyRXh6Nh/Vh+7YVCN9rxEfr1zZIabFOEYFlfCZr4R6XXFRUhje8TJ612+0I/4eeDhj5oI1S2ILu31w7U8ztYv656cngT1jWD94UTbbIzJTyDvyoTkcvvaxADr5vyffIhzTSRxH5C9sVDJOv1wrokEGkF60UsjkppYRlEtrAqe8ng+jfdeTA=="
    print(decrypt(blob))
