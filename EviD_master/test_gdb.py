from Core.GdbBridge import GdbDebugger

pid_num = int(input())
dbg = GdbDebugger(
    pid=pid_num,
    entry_function="main",
    symbol_path="/home/workspace/Testcase/test2/syms.o",
    base_addr="0x555555554000",
    plugin_path="/home/workspace/ida_util/trace_break2.py"
)

dbg.attach_and_setup()
r = dbg.interact('x/5i $pc')
print(r)
print("\n\n\n")
r = dbg.interact('x/5i $pc')
print(r.get("stdout"))
print("\n\n\n")
