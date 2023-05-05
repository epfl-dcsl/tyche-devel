#!/bin/python3

from enum import Enum

""" The different printing formats """
class FormatSize(Enum):
    b    = 1
    w    = 4
    g    = 8
    

""" Guests supported by our script """
class Guests(Enum):
    RAWC = "rawc"
    LINUX = "linux"

""" Memory offsets, for the moment we have an enum.
    A better solution would have tyche dump them in a file at startup,
    so that we can read them."""
class VirtOffsets(Enum):
    tyche = 0x18000000000
    linux = 0xffffffff80000000

AddressContext = {
    "tyche_virt": -1 * VirtOffsets.tyche.value,
    "tyche_phys": 0,
    "guest_phys": 0,
    "guest_virt": 0,
    "linux_virt": -1 * VirtOffsets.linux.value, 
        }

QEMU_RAMFILE="/tmp/tyche"


from scripts.capture_variable import *
#""" Global static rust variable that we want to capture right after instantiation.
#This is done automatically by the tyche_set_convenience_vars command as we reach
#the tyche_hook_done function."""
#CAPTURED_VARIABLES = [
#        "STAGE2_POFF",
#        "STAGE2_VOFF",
#        ]

def get_global_var(name):
    infos = gdb.execute("info variables -q "+name, to_string=True).split()
    address = infos[-2]
    res = gdb.execute("x/1gx "+address, to_string=True).split()[-1]
    return int(res, 16)

def set_global_var(name):
    value = get_global_var(name)
    gdb.execute("set $tyche_"+name+"="+hex(value))

def get_convenience(name):
     return int(gdb.execute("p/x $tyche_"+name, to_string=True).split()[-1], 16)

""" GDB initialization command called right at the hook after loading the guest.
This command captures the value of certain globals that would need to be
accessed, even when we are running the guest.
It captures the global's value and sets it inside a convenience gdb var prefixed
with `tyche_`."""
class TycheSetConvenienceVars(gdb.Command):
    def __init__(self):
        super (TycheSetConvenienceVars, self).__init__("tyche_set_convenience_vars", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        for e in CAPTURED_VARIABLES:
            set_global_var(e)

class TycheLoadStage2(gdb.Command):
    def __init__(self):
        super (TycheLoadStage2, self).__init__("tyche_load_stage2", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        offset = get_convenience("STAGE2_VOFF")
        gdb.execute("add-symbol-file target/x86_64-unknown-kernel/release/tyche")

""" Starts the remote gdb session attached to the debugger/debugger executable.
The remote gdb session executes until QEMU file-backed memory is mmaped into
the process'address space. It then blocks on gdb_block function and starts the server."""
class TycheStartServer(gdb.Command):
    def __init__(self):
        super (TycheStartServer, self).__init__("tyche_start_server", gdb.COMMAND_USER)

    """@warning there is a continue to avoid the main breakpoint.
    If you do not have one set, we should remove that."""
    def invoke(self, arg, from_tty):
        import os
        # Get the name of the binary
        name = gdb.execute("p $tyche_guest_image", to_string=True).split()[-1]
        goff = get_convenience("GUEST_START")
        with open("/tmp/guest_info", 'w') as fd:
            fd.write(name+"\n")
            for c in CAPTURED_VARIABLES:
                v = get_convenience(c)
                fd.write(hex(v)+"\n")
        command = [
                "nohup",
                "gdb",
                "./debugger/debugger",
                "-ex",
                '"source scripts/debugger.gdb"',
                "-ex",
                '"start"',
                "-ex",
                '"c"',
                ">",
                "/tmp/debugger.out",
                "2>&1",
                "&"
                ]
        os.system(" ".join(command)) 
        # TODO Load stage 2 file 

""" Receiving the entire message """
def recvall(sock):
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            # either 0 or end of data
            break
    return data.decode().strip()

""" Sends a command to the remote debugger server and waits for the response """
def execute_command(cmd):
    import sys
    import socket
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ("localhost", 5678)
    sock.connect(server_address)
    try:
        sock.sendall(cmd.encode())
        response = recvall(sock)
        print(response)
    finally:
        sock.close()


def create_stack_cmd(offset):
    # Get the registers.
    rsp = int(gdb.execute("p/x $rsp", to_string=True).split()[-1], 16)
    rbp = int(gdb.execute("p/x $rbp", to_string=True).split()[-1], 16)

    # Get the starting values
    gstack_phys = get_convenience("GUEST_STACK_PHYS")
    gstack_virt = get_convenience("GUEST_STACK_VIRT")

    # Compute offsets
    diff_rsp = (rsp - gstack_virt)
    diff_rbp = (rbp - gstack_virt)
    start = gstack_phys+offset
    cmd = "STACK "+hex(start+diff_rsp) + " "+hex(start+diff_rbp)
    return cmd

def create_print_log(cmd):
    # format is PLOG size
    size = int(cmd.split()[-1])
    # Get the symbol address for the log
    addr = int(gdb.execute("p &__log_buf", to_string=True).split()[-2], 16)
    # Remove the offset
    guest_start = get_convenience("GUEST_START")
    addr = addr - 0xffffffff80000000 + guest_start 
    cmd = "x/"+str(size)+"s @"+hex(addr)+"@"
    print("The command ", cmd)
    return cmd

""" Adds an offset to a `@` wrapped address """
def update_address(wrapped, offset):
    assert wrapped.startswith("@")
    assert wrapped.endswith("@")
    try:
        prev = int(wrapped[1:-1], 16)
        value = prev + offset
        print("[CLIENT]", hex(prev), "->", hex(value), "(+", hex(offset), ")")
        return value
    except:
        print("[CLIENT] Error parsing `", wrapped, "`")
    return wrapped[1:-1]

""" This command forwards gdb commands to the debugger server. """
class TycheClient(gdb.Command):
    def __init__(self):
        super (TycheClient, self).__init__("tyche", gdb.COMMAND_USER)

    """ The format for this command is: tyche `context` `command`.
    Moreover, we allow automatic translation of addresses surrounded by @s """
    def invoke(self, arg, from_tty):
        # Update the guest address.
        guest_start = get_convenience("GUEST_START")
        args = arg.split()

        # Find the context & compute the offset
        context = args[0]
        offset = AddressContext[context]
        if context.startswith("guest_"):
            offset = offset + guest_start

        # Replace addresses according to context
        for i, a in enumerate(args):
            if a.startswith("@") and a.endswith("@"):
                value = update_address(a, offset)
                replace = "@"+hex(value)+"@"
                args[i] = replace

        cmd = " ".join(args[1:])

        # Special commands
        if cmd == "BT":
            cmd = create_stack_cmd(offset)
        if cmd.startswith("PLOG"):
            cmd = create_print_log(cmd) 

        # Now send the command to the remote server without the context
        execute_command(cmd) 


#TycheGuestMemoryDump()
TycheSetConvenienceVars()
TycheStartServer()
TycheClient()
TycheLoadStage2()
