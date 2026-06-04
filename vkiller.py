import time
from pwn import *
import itertools
context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

main_opcodes = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
fun_opcodes = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
cool_worker_op = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
regs_arr = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
file_path = "file_path"

c_changer = -1
reg_changer = -1
cool_worker = -1
cool_buf_worker = -1

exit_num = -1
read1 = -1
read2 = -1

a0 = -1
a2 = -1


print("c_changer guessing")
for i in fun_opcodes:
    p = process(file_path)
    pld = struct.pack("<3B", 0x33, ord('/'), i) #reg val op
    p.send(pld)
    p.clean(timeout=2)
    p.close()
    print(p.poll())
    if p.poll() != 1:
        c_changer = i

print("reg_changer guessing")
for i in fun_opcodes:
    p = process(file_path)
    pld = struct.pack("<3B", 0x01, ord('/'), i) #reg val op
    p.send(pld)
    p.clean(timeout=2)
    p.close()
    print(p.poll())
    if p.poll() != 1 and c_changer != i:
        reg_changer = i

print("cool_worker guessing")
fun_opcodes.remove(reg_changer)
fun_opcodes.remove(c_changer)
for i in fun_opcodes:
    print()
    for u in main_opcodes:
        p = process(file_path)
        pld = struct.pack("<3B", u, ord('/'), i) #mini_op trash op
        p.send(pld)
        p.clean(timeout=2)
        p.close()
        print(p.poll())
        if p.poll() == 0:
            cool_worker = i
            exit_num = u
        if p.poll() != 1:
            cool_worker_op.remove(u)

fun_opcodes.remove(cool_worker)
print("cool_buf_worker guessing")
for i in fun_opcodes:
    p = process(file_path)
    pld = struct.pack("<3B", 0, 0, i) #reg val op
    p.send(pld)
    p.clean(timeout=2)
    p.close()
    print(p.poll())
    if p.poll() != 1:
        cool_buf_worker = i
fun_opcodes.remove(cool_buf_worker)

print("a0 guessing")
for i in regs_arr:
    p = process(file_path)
    pld = struct.pack("<3B", i, 0x33, reg_changer)
    pld += struct.pack("<3B", exit_num, 0x03, cool_worker)
    p.send(pld)
    p.clean(timeout=2)
    p.close()
    print(p.poll())
    if p.poll() == 0x33:
        a0 = i
regs_arr.remove(a0)

print("read guessing")
for i in regs_arr:
    print()
    temp_arr = []
    for u in cool_worker_op:
        p = process(file_path)
        pld = struct.pack("<3B", i, 0x11, reg_changer)
        pld += struct.pack("<3B", u, 0x11, cool_worker)
        p.send(pld)
        p.clean(timeout=2)
        p.close()
        print(p.poll())
        temp_arr.append(p.poll())
    if temp_arr.count(-9) == 2:
        read1 = temp_arr.index(-9)
        read2 = cool_worker_op[temp_arr.index(-9, read1 + 1)]
        read1 = cool_worker_op[read1]
        a2 = i
cool_worker_op.remove(read1)
cool_worker_op.remove(read2)
regs_arr.remove(a2)

print()
for i in cool_worker_op:
    for u in [read1, read2]:
        for y in cool_worker_op:
            p = process(file_path)
            pld = struct.pack("<3B", a2, 6, reg_changer)
            pld += struct.pack("<3B", u, a2, cool_worker) #read

            pld += struct.pack("<3B", a0, 0, reg_changer)
            pld += struct.pack("<3B", y, a0, cool_worker)#open

            pld += struct.pack("<3B", a2, 80, reg_changer)
            pld += struct.pack("<3B", u, a2, cool_worker)#read

            pld += struct.pack("<3B", a0, 1, reg_changer)
            pld += struct.pack("<3B", i, a2, cool_worker)
            p.send(pld)
            time.sleep(0.2)
            p.send(b"/flag")
            data = p.clean(timeout=2)
            p.close()
            print(p.poll())
            if b'pwn' in data:
                print(data)



print("c_changer:", hex(c_changer), " reg_changer:", hex(reg_changer), " cool_worker:", hex(cool_worker),
      " cool_buf_worker:", hex(cool_buf_worker))

print("exit_num:", hex(exit_num), " read1:", hex(read1), " read2:", hex(read2))

print("a0 =", hex(a0))
print("a2 =", hex(a2))
print(cool_worker_op)
