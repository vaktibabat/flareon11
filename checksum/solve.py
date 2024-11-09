import base64
from hashlib import sha256
from z3 import *

HEX_CONST = 0x5d1745d1745d1746

TARGET = b"cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA=="
TARGET_DECODED = base64.b64decode(TARGET)

# Solving w/z3
s = Solver()
correct_checksum = [BitVec(f"checksum_{i}", 8) for i in range(64)]
xor_arr = b"FlareOn2024"

for i in range(64):
    j = i - 11 * (((i * HEX_CONST) >> 64) >> 2)

    s.add(correct_checksum[i] ^ xor_arr[j] == TARGET_DECODED[i])

print(s.check())
model = s.model()

ans = ""

for var in correct_checksum:
    ans += chr(model[var].as_long())

print(ans)
