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
