import sys
import binascii
from capstone import *

z = binascii.a2b_hex(sys.argv[1])
r = ''

md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(z, 0x1000)
    r = r + "{} {}\n".format(i.mnemonix, i.opstr)

print(r)
print(binascii.b2a_hex(r.encode('ascii')))
