from pwn import *
from sys import argv

if not 2 <= len(argv) <= 4:
    print("Error: Invalid number of arguments.")
    print("Correct usage: canary-checker [file] {amount} {repeats}")
    exit()

context.log_level = 'WARN'

executable = argv[1]
amount = 25 if not len(argv) > 2 else int(argv[2])
repeats = 2 if not len(argv) > 3 else int(argv[3])

offsets = {}

for x in range(repeats):
    for x in range(int(amount)):
        p = ELF("./" + executable).process()
        p.clean(0.2)
        p.sendline("%" + str(x) + "$lx")
        if value.endswith("00"):
            if x not in offsets:
                offsets[x] = set()
            offsets[x].add(value)

print("#### Possible Due To Changing Value ####")
for x in offsets:
    if len(offsets[x]) == repeats:
        print(str(x) + ": " + ", ".join(offsets[x]))
