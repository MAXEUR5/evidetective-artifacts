import idc  # type: ignore
import ida_kernwin  # type: ignore

idc.msg("This is a message via idc.msg().\n")
ida_kernwin.msg("This is a message via ida_kernwin.msg().\n")