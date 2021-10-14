# Solution to Reverse Engineering CTF 2020

## Step 1 - Runing the File

Run `a.out`
```console
meinzecp@csse332-VirtualBox:~/Documents/ctfs/google_2020_re# ./a.out
Flag: test
FAILURE
```
Not much here. Start using basic flag finding techniques.
Using `ptrace`, `ltrace`, and `strace`, I could not find any flag in plaintext.

## Step 2 - Using Ghidra for Disassembly

Open up Ghidra, start a new project, and import the file.
```c
ulong main(void)

{
  int iVar1;
  uint uVar2;
  undefined auVar3 [16];
  undefined user_input [16];
  undefined4 local_28;
  undefined4 uStack36;
  undefined4 uStack32;
  undefined4 uStack28;
  
  printf("Flag: ");
  __isoc99_scanf(&DAT_0010200b,user_input);
  auVar3 = pshufb(user_input,SHUFFLE);
  auVar3 = CONCAT412(SUB164(auVar3 >> 0x60,0) + ADD32._12_4_,
                     CONCAT48(SUB164(auVar3 >> 0x40,0) + ADD32._8_4_,
                              CONCAT44(SUB164(auVar3 >> 0x20,0) + ADD32._4_4_,
                                       SUB164(auVar3,0) + ADD32._0_4_))) ^ XOR;
  local_28 = SUB164(auVar3,0);
  uStack36 = SUB164(auVar3 >> 0x20,0);
  uStack32 = SUB164(XOR >> 0x40,0);
  uStack28 = SUB164(XOR >> 0x60,0);
  iVar1 = strncmp(user_input,(char *)&local_28,0x10);
  if (iVar1 == 0) {
    uVar2 = strncmp((char *)&local_28,EXPECTED_PREFIX,4); // EXPECTED_PREFIX = "CTF{"
    if (uVar2 == 0) {
      puts("SUCCESS");
      goto LAB_00101112;
    }
  }
  uVar2 = 1;
  puts("FAILURE");
LAB_00101112:
  return (ulong)uVar2;
}
```

First thing I noticed is that the input is being scrambled by `pshufb` aliong with other concatenations and shifts.
This will not help me in any way trying to use my brain.

## Step 3 - Find the Arguments Needed for angr

I created a Python executable with `angr` that explores different routes through the assembly. It then looks for a path that leads to the "SUCCESS" location of the program.

The "SUCCESS" address is found in the assembly as follows:
```assembly
                             LAB_0010111d                                    XREF[1]:     001010fe(j)  
        0010111d 48 8d 3d        LEA        RDI,[s_SUCCESS_00102010]                         = "SUCCESS"
                 ec 0e 00 00
        00101124 e8 17 ff        CALL       puts                                             int puts(char * __s)
                 ff ff
```

The "FAILURE address is found in the asseembly as follows (NOTE: we want to avoid this section):
```assembly
                             LAB_00101100                                    XREF[1]:     001010e3(j)  
        00101100 48 8d 3d        LEA        RDI,[s_FAILURE_00102018]                         = "FAILURE"
                 11 0f 00 00
        00101107 41 bc 01        MOV        R12D,0x1
                 00 00 00
        0010110d e8 2e ff        CALL       puts                                             int puts(char * __s)
                 ff ff

```
I also found out that the flag length is 0x10 by looking at the buffer size and `strncmp`. Removing the NULL terminator, the flag length should be 15.
The last argument that `angr` needs is the base address, which is found to be 0x100000 at the top of the dissassmbled code.

## Step 4 - Create the python Script
```python
#!usr/bin/env python
#Author: Christian Meinzen

import angr
import claripy

flag_len = 15
base_addr = 0x00100000
success_addr = 0x0010111d
fail_addr = 0x00101100

new_proj = angr.Project("./a.out", main_opts={"base_addr" : base_addr})

flag_vals = [claripy.BVS(f"flag_val{i}", 8) for i in range(flag_len)]
full_flag = claripy.Concat(*flag_vals + [claripy.BVV(b"\n")])

new_state = new_proj.factory.full_init_state(args=["./a.out"], add_options = angr.options.unicorn, stdin=full_flag)

for c in flag_vals:
    new_state.solver.add(c >= ord("!"))
    new_state.solver.add(c <= ord("~"))

simulation_mgr = new_proj.factory.simulation_manager(new_state)
simulation_mgr.explore(find = success_addr, avoid fail_addr)
if len(simulation_mgr.found) > 0:
    for guess in simulation_mgr.found:
        print(guess.posix.dumps(0)) #Note: '0' is file descriptor for sd_input

```

## Step 5 - Run the Script to Find the Flag
We run the script and get the flag within a few seconds:
```console
(angr) rmeinzecp@csse332-VirtualBox:~/Documents/ctfs/google_2020_re# python3 solve.py
WARNING | 2020-08-23 15:13:00,365 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-08-23 15:13:00,366 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-08-23 15:13:00,366 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-08-23 15:13:00,367 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-08-23 15:13:00,367 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-08-23 15:13:00,368 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffefff8 with 1 unconstrained bytes referenced from 0x299d80 (explicit_bzero+0x8c40 in libc.so.6 (0x99d80))
WARNING | 2020-08-23 15:13:00,425 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffefff9 with 7 unconstrained bytes referenced from 0x299dad (explicit_bzero+0x8c6d in libc.so.6 (0x99dad))
WARNING | 2020-08-23 15:13:05,064 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0000 with 48 unconstrained bytes referenced from 0x28a7f0 (strncmp+0x0 in libc.so.6 (0x8a7f0))
WARNING | 2020-08-23 15:13:05,086 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffffffffff0030 with 16 unconstrained bytes referenced from 0x28a7f0 (strncmp+0x0 in libc.so.6 (0x8a7f0))
b'CTF{S1MDf0rM3!}\n'
```
