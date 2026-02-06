cwe121_api_ans_cache = [
    {
        "_ITM_deregisterTMCloneTable": {
            "type": "neither",
            "reason": "GCC transactional memory runtime symbol; does not read external input or write to caller-provided stack buffers."
        }
    },
    {
        "_ITM_registerTMCloneTable": {
            "type": "neither",
            "reason": "GCC transactional memory runtime symbol; unrelated to input or stack-buffer writes."
        }
    },
    {
        "_Unwind_Resume": {
            "type": "neither",
            "reason": "C++ unwinding runtime; continues stack unwinding but does not act as an input primitive or buffer-writing sink."
        }
    },
    {
        "_ZNSt8__detail15_List_node_base7_M_hookEPS0_": {
            "type": "neither",
            "reason": "libstdc++ list-internal hook; container metadata operation, not an external data source or stack-overflow sink."
        }
    },
    {
        "_ZSt17__throw_bad_allocv": {
            "type": "neither",
            "reason": "Throws bad_alloc exception; no external input is read and no user buffer is written."
        }
    },
    {
        "_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base": {
            "type": "neither",
            "reason": "libstdc++ red-black tree iterator helper; operates on internal nodes, not on user-controlled stack buffers."
        }
    },
    {
        "_ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base": {
            "type": "neither",
            "reason": "libstdc++ red-black tree iterator helper; does not read external input or write into caller-provided buffers."
        }
    },
    {
        "_ZSt20__throw_length_errorPKc": {
            "type": "neither",
            "reason": "Throws length_error exception; no I/O and no writes into user stack buffers."
        }
    },
    {
        "_ZSt28__throw_bad_array_new_lengthv": {
            "type": "neither",
            "reason": "Throws bad_array_new_length; no external data read and no potential for stack-buffer writes."
        }
    },
    {
        "_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_": {
            "type": "neither",
            "reason": "libstdc++ tree insertion/rebalance internals; manipulates container nodes only, not caller-owned stack buffers."
        }
    },
    {
        "_ZTVN10__cxxabiv117__class_type_infoE": {
            "type": "neither",
            "reason": "C++ RTTI vtable symbol; metadata only, not an input primitive or buffer-writing routine."
        }
    },
    {
        "_ZTVN10__cxxabiv120__si_class_type_infoE": {
            "type": "neither",
            "reason": "C++ RTTI vtable symbol; unrelated to external input or stack-buffer writes."
        }
    },
    {
        "_ZdlPvm": {
            "type": "neither",
            "reason": "C++ operator delete(void*, size_t); frees heap memory without copying data into stack buffers."
        }
    },
    {
        "_Znwm": {
            "type": "neither",
            "reason": "C++ operator new(size_t); allocates heap memory but does not read external data or write to caller-provided stack buffers."
        }
    },
    {
        "__ctype_b_loc": {
            "type": "neither",
            "reason": "Returns pointer to ctype classification table; no external input read and no stack-buffer write semantics."
        }
    },
    {
        "__cxa_begin_catch": {
            "type": "neither",
            "reason": "C++ exception-handling runtime helper; manipulates exception state only, not user buffers or I/O."
        }
    },
    {
        "__cxa_end_catch": {
            "type": "neither",
            "reason": "C++ exception-handling runtime helper; does not introduce input or write into caller-provided buffers."
        }
    },
    {
        "__cxa_finalize": {
            "type": "neither",
            "reason": "Exit-time finalizer dispatcher; invokes destructors but is not a source or a stack-overflow sink."
        }
    },
    {
        "__cxa_pure_virtual": {
            "type": "neither",
            "reason": "Abort handler for pure virtual calls; it terminates rather than performing I/O or buffer writes."
        }
    },
    {
        "__cxa_rethrow": {
            "type": "neither",
            "reason": "Re-throws the current exception; no new external data is read and no stack buffers are written."
        }
    },
    {
        "__gmon_start__": {
            "type": "neither",
            "reason": "gmon/profiling initialization hook; unrelated to external input or caller buffer writes."
        }
    },
    {
        "__gxx_personality_v0": {
            "type": "neither",
            "reason": "C++ exception personality function; participates in unwinding decisions but is not a source or sink."
        }
    },
    {
        "__isoc23_fscanf": {
            "type": "source",
            "reason": "Reads formatted data from a FILE* stream; external data from stdin or files enters the program state here."
        }
    },
    {
        "__isoc23_fscanf": {
            "type": "sink",
            "reason": "Writes parsed fields into caller-provided storage (including stack buffers); unsafe formats or width specifiers can overflow stack buffers (CWE-121)."
        }
    },
    {
        "__isoc99_fscanf": {
            "type": "source",
            "reason": "Classic fscanf-style function; reads formatted data from FILE*, bringing external/user-controlled data into the program."
        }
    },
    {
        "__isoc99_fscanf": {
            "type": "sink",
            "reason": "Stores parsed results into caller-supplied addresses; with %s/%[...] and missing or excessive width limits, stack-based buffers may overflow (CWE-121)."
        }
    },
    {
        "__isoc99_sscanf": {
            "type": "sink",
            "reason": "Parses from a caller-supplied string into provided addresses; wrong or missing limits in %s/%[...] can overflow stack buffers used as output storage (CWE-121)."
        }
    },
    {
        "__isoc99_swscanf": {
            "type": "sink",
            "reason": "Wide-character sscanf variant; writes parsed data into caller buffers, and unsafe wide-string formats or widths can overflow stack-based buffers."
        }
    },
    {
        "__libc_start_main": {
            "type": "neither",
            "reason": "Process entry helper that calls main and init/fini routines; it does not itself read external input into user buffers or write into stack buffers."
        }
    },
    {
        "__stack_chk_fail": {
            "type": "neither",
            "reason": "Stack protector failure handler; indicates an overflow but is not an input source or buffer-writing primitive."
        }
    },
    {
        "atoi": {
            "type": "neither",
            "reason": "Converts a C-string to int; reads from an existing in-memory string and performs no writes into caller buffers."
        }
    },
    {
        "calloc": {
            "type": "neither",
            "reason": "Allocates and zero-initializes heap memory; does not read external input and does not operate on caller stack buffers."
        }
    },
    {
        "exit": {
            "type": "neither",
            "reason": "Terminates the process; does not perform external-input reads or writes into user-controlled buffers."
        }
    },
    {
        "fgets": {
            "type": "source",
            "reason": "Reads characters from a FILE* (e.g., stdin or a file) into a buffer; introduces external/user-controlled input into the program."
        }
    },
    {
        "fgets": {
            "type": "sink",
            "reason": "Writes up to n-1 characters plus a terminator into the destination buffer; if the passed length exceeds the true stack-buffer size (due to miscalculation or corruption), this can overflow the stack (CWE-121)."
        }
    },
    {
        "free": {
            "type": "neither",
            "reason": "Frees heap memory referenced by a pointer; does not read external input or write to stack buffers."
        }
    },
    {
        "iswxdigit": {
            "type": "neither",
            "reason": "Wide-character classification routine; only inspects a value and does not perform any I/O or writes into caller buffers."
        }
    },
    {
        "memcpy": {
            "type": "sink",
            "reason": "Copies n bytes from src to dest; if dest points to a stack buffer and n exceeds its capacity, a stack-based buffer overflow occurs (CWE-121)."
        }
    },
    {
        "memmove": {
            "type": "sink",
            "reason": "Overlap-safe copy of n bytes to dest; still writes to dest, and an oversized n with a stack-based dest leads to CWE-121."
        }
    },
    {
        "printf": {
            "type": "neither",
            "reason": "Formats and prints to stdout; does not write into caller-provided buffers (it is relevant to format-string issues, not CWE-121 stack overflows)."
        }
    },
    {
        "puts": {
            "type": "neither",
            "reason": "Writes a string to stdout followed by a newline; does not write into user-provided memory buffers."
        }
    },
    {
        "rand": {
            "type": "neither",
            "reason": "Returns a pseudo-random integer; no external input and no writes to caller buffers."
        }
    },
    {
        "snprintf": {
            "type": "sink",
            "reason": "Writes formatted output to a destination buffer bounded by maxlen; if maxlen does not reflect the real stack-buffer size (e.g., miscalculated or corrupted), it can overflow the stack (CWE-121)."
        }
    },
    {
        "srand": {
            "type": "neither",
            "reason": "Seeds the pseudo-random number generator; does not read external input or write into caller buffers."
        }
    },
    {
        "strcat": {
            "type": "sink",
            "reason": "Appends src to dest without enforcing total size; if dest is a stack buffer and the combined string exceeds its capacity, a stack overflow occurs (CWE-121)."
        }
    },
    {
        "strcpy": {
            "type": "sink",
            "reason": "Copies src to dest without bounds checking; if dest is a stack buffer and src is too long, it overflows the stack (CWE-121)."
        }
    },
    {
        "strlen": {
            "type": "neither",
            "reason": "Computes the length of a string by reading memory until a null terminator; performs no writes into buffers."
        }
    },
    {
        "strncat": {
            "type": "sink",
            "reason": "Appends at most n characters plus a terminator to dest; if n does not account for the existing contents and stack-buffer size, it can overflow the destination (CWE-121)."
        }
    },
    {
        "strncpy": {
            "type": "sink",
            "reason": "Copies up to n bytes from src to dest; if n is larger than the stack-buffer capacity, or length logic is wrong, it can write past the end of the stack buffer (CWE-121)."
        }
    },
    {
        "time": {
            "type": "neither",
            "reason": "Returns the current time as time_t; does not write into caller-provided buffers and is not attacker-controlled input."
        }
    },
    {
        "wcscpy": {
            "type": "sink",
            "reason": "Copies a wide-character string to dest without bounds checking; if dest is a stack-based wide buffer and src is longer, stack-based overflow occurs (CWE-121)."
        }
    },
    {
        "wcslen": {
            "type": "neither",
            "reason": "Computes the length of a wide-character string by reading until a terminator; does not write into buffers."
        }
    },
    {
        "wprintf": {
            "type": "neither",
            "reason": "Wide-character printf; writes to stdout instead of caller buffers, so it is not a CWE-121 stack-overflow sink."
        }
    }
]


cwe122_api_ans_cache = [
    {
        "_ITM_deregisterTMCloneTable": {
            "type": "neither",
            "reason": "GCC transactional memory runtime symbol; does not ingest external input and does not write into application-managed buffers (heap or otherwise)."
        }
    },
    {
        "_ITM_registerTMCloneTable": {
            "type": "neither",
            "reason": "GCC transactional memory runtime symbol; unrelated to external-input acquisition or buffer-writing behavior relevant to heap overflows."
        }
    },
    {
        "_Unwind_Resume": {
            "type": "neither",
            "reason": "C++/GCC unwinding runtime; controls exception unwinding flow and does not read external input or perform writes into caller-provided heap buffers."
        }
    },
    {
        "_ZNSt8__detail15_List_node_base7_M_hookEPS0_": {
            "type": "neither",
            "reason": "libstdc++ list-internal hook operation; manipulates container node links, not external input and not a heap-buffer write primitive."
        }
    },
    {
        "_ZSt17__throw_bad_allocv": {
            "type": "neither",
            "reason": "Throws std::bad_alloc; no external input is read and no data is copied/written into heap buffers."
        }
    },
    {
        "_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base": {
            "type": "neither",
            "reason": "libstdc++ red-black tree iterator helper; operates on internal node pointers only, not an input source or heap-overflow sink."
        }
    },
    {
        "_ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base": {
            "type": "neither",
            "reason": "libstdc++ red-black tree iterator helper; does not ingest external data and does not write into application heap buffers."
        }
    },
    {
        "_ZSt20__throw_length_errorPKc": {
            "type": "neither",
            "reason": "Throws std::length_error; exception signaling only, not external input and not a heap buffer write/copy sink."
        }
    },
    {
        "_ZSt28__throw_bad_array_new_lengthv": {
            "type": "neither",
            "reason": "Throws bad_array_new_length; exception path only, not a data source and not a heap-writing sink."
        }
    },
    {
        "_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_": {
            "type": "neither",
            "reason": "libstdc++ tree insertion/rebalance internals; manipulates tree metadata, not external input and not a heap-buffer write primitive."
        }
    },
    {
        "_ZTVN10__cxxabiv117__class_type_infoE": {
            "type": "neither",
            "reason": "C++ RTTI vtable symbol; type metadata only, unrelated to external-input sources or heap-buffer write sinks."
        }
    },
    {
        "_ZTVN10__cxxabiv120__si_class_type_infoE": {
            "type": "neither",
            "reason": "C++ RTTI vtable symbol; type metadata only, not an input primitive and not a heap-overflow sink."
        }
    },
    {
        "_ZdaPv": {
            "type": "neither",
            "reason": "C++ operator delete[](void*); frees heap memory but does not read external input or copy/write data into heap buffers."
        }
    },
    {
        "_ZdlPvm": {
            "type": "neither",
            "reason": "C++ sized operator delete(void*, size_t); deallocates memory without writing into buffers or ingesting external input."
        }
    },
    {
        "_Znam": {
            "type": "neither",
            "reason": "C++ operator new[](size_t); allocates heap memory but does not itself copy data into buffers or read external input (overflow occurs at subsequent writes)."
        }
    },
    {
        "_Znwm": {
            "type": "neither",
            "reason": "C++ operator new(size_t); allocates heap memory but is not an external-input source and not a heap-buffer write/copy sink."
        }
    },
    {
        "__ctype_b_loc": {
            "type": "neither",
            "reason": "Returns a pointer to locale-dependent ctype classification table; no external input is read and no heap buffer is written."
        }
    },
    {
        "__cxa_begin_catch": {
            "type": "neither",
            "reason": "C++ exception runtime helper; manages exception state only, not an input source and not a heap-overflow sink."
        }
    },
    {
        "__cxa_end_catch": {
            "type": "neither",
            "reason": "C++ exception runtime helper; ends catch handling and does not perform buffer writes or external input reads."
        }
    },
    {
        "__cxa_finalize": {
            "type": "neither",
            "reason": "Finalizer dispatcher invoked at exit/unload; not a data source and not a heap-buffer writing API."
        }
    },
    {
        "__cxa_pure_virtual": {
            "type": "neither",
            "reason": "Handler for pure virtual calls (typically terminates); not related to external input or heap-buffer writes."
        }
    },
    {
        "__cxa_rethrow": {
            "type": "neither",
            "reason": "Rethrows the current exception; control-flow only, not external input and not a heap overflow sink."
        }
    },
    {
        "__gmon_start__": {
            "type": "neither",
            "reason": "Profiling initialization hook; unrelated to external input acquisition or heap-buffer write operations."
        }
    },
    {
        "__gxx_personality_v0": {
            "type": "neither",
            "reason": "C++ exception personality function; participates in unwinding decisions but does not read external input or write to heap buffers."
        }
    },
    {
        "__isoc23_fscanf": {
            "type": "source",
            "reason": "Reads formatted data from a FILE* stream (e.g., stdin or a file), introducing external/user-controlled data into the program state."
        }
    },
    {
        "__isoc23_fscanf": {
            "type": "sink",
            "reason": "Writes parsed fields into caller-provided addresses; with %s/%[...] and missing/incorrect width limits, it can overflow destination buffers including heap allocations (CWE-122)."
        }
    },
    {
        "__isoc99_fscanf": {
            "type": "source",
            "reason": "Classic fscanf-family input primitive; reads external data from a FILE* stream into program variables."
        }
    },
    {
        "__isoc99_fscanf": {
            "type": "sink",
            "reason": "Stores parsed output into caller-provided memory; unsafe formats (e.g., %s without width) can write past heap buffer bounds when destinations are heap-allocated (CWE-122)."
        }
    },
    {
        "__isoc99_sscanf": {
            "type": "sink",
            "reason": "Parses from a caller-supplied string and writes results into provided output addresses; incorrect/missing width specifiers for %s/%[...] can overflow heap-resident destination buffers (CWE-122)."
        }
    },
    {
        "__isoc99_swscanf": {
            "type": "sink",
            "reason": "Wide-character sscanf variant; writes parsed wide strings/fields into caller buffers, and unsafe width handling can overflow heap-allocated destinations (CWE-122)."
        }
    },
    {
        "__libc_start_main": {
            "type": "neither",
            "reason": "Process entry helper that dispatches to main/init/fini; not an external-input source and not a heap-buffer writing sink."
        }
    },
    {
        "__stack_chk_fail": {
            "type": "neither",
            "reason": "Stack protector failure handler; indicates corruption but does not read external input or write into heap buffers."
        }
    },
    {
        "atoi": {
            "type": "neither",
            "reason": "Converts an existing in-memory C-string to int; does not read external I/O and does not write into caller buffers."
        }
    },
    {
        "exit": {
            "type": "neither",
            "reason": "Terminates the process; not an input source and not a heap-buffer write/copy sink."
        }
    },
    {
        "fgets": {
            "type": "source",
            "reason": "Reads characters from a FILE* stream (stdin/file) into memory, introducing external/user-controlled input into the program."
        }
    },
    {
        "fgets": {
            "type": "sink",
            "reason": "Writes up to n-1 bytes plus a terminator into the destination buffer; if n exceeds the actual heap allocation size (due to wrong size tracking), it can write past heap bounds (CWE-122)."
        }
    },
    {
        "free": {
            "type": "neither",
            "reason": "Deallocates heap memory; does not ingest external input and does not copy/write data into heap buffers."
        }
    },
    {
        "iswxdigit": {
            "type": "neither",
            "reason": "Wide-character classification routine; inspects a value only and performs no external input read or heap-buffer write."
        }
    },
    {
        "malloc": {
            "type": "neither",
            "reason": "Allocates heap memory but does not read external input or write/copy data into existing buffers; CWE-122 overflows occur at subsequent writes."
        }
    },
    {
        "memcpy": {
            "type": "sink",
            "reason": "Copies n bytes from src to dest; if dest points to a heap buffer smaller than n, it writes past heap bounds (CWE-122)."
        }
    },
    {
        "memmove": {
            "type": "sink",
            "reason": "Overlap-safe copy to dest; still writes n bytes, and an oversized n relative to a heap allocation causes heap-based buffer overflow (CWE-122)."
        }
    },
    {
        "printf": {
            "type": "neither",
            "reason": "Formats and prints to stdout; it does not write into caller-provided memory buffers (heap or stack), so it is not a CWE-122 buffer-write sink."
        }
    },
    {
        "puts": {
            "type": "neither",
            "reason": "Writes a string to stdout; does not write into application-managed buffers and is not a heap overflow sink."
        }
    },
    {
        "rand": {
            "type": "neither",
            "reason": "Returns a pseudo-random integer; not an external-input source and does not write into caller-provided buffers."
        }
    },
    {
        "snprintf": {
            "type": "sink",
            "reason": "Writes formatted output into a destination buffer up to maxlen; if maxlen is incorrectly larger than the actual heap allocation size of s, it can write past heap bounds (CWE-122)."
        }
    },
    {
        "srand": {
            "type": "neither",
            "reason": "Seeds the PRNG; does not ingest external input and does not write into heap buffers."
        }
    },
    {
        "strcat": {
            "type": "sink",
            "reason": "Appends src to dest without enforcing total capacity; if dest is heap-allocated and the combined string exceeds its allocation, it overflows the heap buffer (CWE-122)."
        }
    },
    {
        "strcpy": {
            "type": "sink",
            "reason": "Copies src to dest without bounds checking; if dest is a heap buffer and src length exceeds its allocation, it causes heap-based buffer overflow (CWE-122)."
        }
    },
    {
        "strlen": {
            "type": "neither",
            "reason": "Computes string length by reading memory until NUL; performs no writes into buffers and is not a heap overflow sink."
        }
    },
    {
        "strncat": {
            "type": "sink",
            "reason": "Appends up to n characters plus a terminator; if n is not computed based on remaining capacity of a heap destination (including existing dest length), it can overflow the heap buffer (CWE-122)."
        }
    },
    {
        "strncpy": {
            "type": "sink",
            "reason": "Copies up to n bytes to dest; if n exceeds the size of a heap allocation for dest, it writes past heap bounds (CWE-122)."
        }
    },
    {
        "time": {
            "type": "neither",
            "reason": "Returns the current time; not an attacker-controlled external input primitive and does not write into heap buffers."
        }
    },
    {
        "wprintf": {
            "type": "neither",
            "reason": "Wide-character printf to stdout; does not write into caller-provided heap buffers and is not a CWE-122 buffer-write sink."
        }
    }
]



cwe78_api_ans_cache = [
    {
        "_ITM_deregisterTMCloneTable": {
            "type": "neither",
            "reason": "GCC transactional memory runtime symbol; it does not read external input and does not execute operating system commands."
        }
    },
    {
        "_ITM_registerTMCloneTable": {
            "type": "neither",
            "reason": "GCC transactional memory runtime symbol; unrelated to external input sources or command execution sinks."
        }
    },
    {
        "_Unwind_Resume": {
            "type": "neither",
            "reason": "C++/GCC exception unwinding helper; affects control flow only and is not an input source or command execution sink."
        }
    },
    {
        "_ZNSt8__detail15_List_node_base7_M_hookEPS0_": {
            "type": "neither",
            "reason": "libstdc++ list internal node hook; manipulates container metadata and does not take external input or execute commands."
        }
    },
    {
        "_ZSt17__throw_bad_allocv": {
            "type": "neither",
            "reason": "Throws std::bad_alloc; error signaling only, with no external input and no command execution semantics."
        }
    },
    {
        "_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base": {
            "type": "neither",
            "reason": "libstdc++ red black tree iterator helper; operates on internal node pointers and is not related to CWE-78 sources or sinks."
        }
    },
    {
        "_ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base": {
            "type": "neither",
            "reason": "libstdc++ red black tree iterator helper; internal data structure navigation only, not an input source or command execution sink."
        }
    },
    {
        "_ZSt20__throw_length_errorPKc": {
            "type": "neither",
            "reason": "Throws std::length_error; no external data is ingested and no OS command is executed."
        }
    },
    {
        "_ZSt28__throw_bad_array_new_lengthv": {
            "type": "neither",
            "reason": "Throws bad_array_new_length; exception handling only, not an input primitive and not a command execution sink."
        }
    },
    {
        "_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_": {
            "type": "neither",
            "reason": "libstdc++ red black tree insertion and rebalancing; manipulates container internals and does not read external input or execute commands."
        }
    },
    {
        "_ZTVN10__cxxabiv117__class_type_infoE": {
            "type": "neither",
            "reason": "C++ RTTI vtable symbol; type metadata only, not an external input source or command execution sink."
        }
    },
    {
        "_ZTVN10__cxxabiv120__si_class_type_infoE": {
            "type": "neither",
            "reason": "C++ RTTI vtable symbol; used for type information and not related to external input or OS command execution."
        }
    },
    {
        "_ZdlPvm": {
            "type": "neither",
            "reason": "C++ sized operator delete; deallocates memory but does not receive external input or trigger command execution."
        }
    },
    {
        "_Znwm": {
            "type": "neither",
            "reason": "C++ operator new; allocates heap memory but is not an input source and does not execute commands."
        }
    },
    {
        "__ctype_b_loc": {
            "type": "neither",
            "reason": "Returns a pointer to the ctype classification table; purely local metadata access with no command execution or external input semantics."
        }
    },
    {
        "__cxa_begin_catch": {
            "type": "neither",
            "reason": "C++ exception handling runtime helper; manages exception state and does not act as an input source or command execution sink."
        }
    },
    {
        "__cxa_end_catch": {
            "type": "neither",
            "reason": "C++ exception handling runtime helper; ends a catch block and does not read external input or execute commands."
        }
    },
    {
        "__cxa_finalize": {
            "type": "neither",
            "reason": "Finalizer dispatcher for exit or shared object unload; calls destructors but does not introduce external input or execute OS commands."
        }
    },
    {
        "__cxa_pure_virtual": {
            "type": "neither",
            "reason": "Handler for pure virtual function calls; typically aborts and does not act as a source or a command execution sink."
        }
    },
    {
        "__cxa_rethrow": {
            "type": "neither",
            "reason": "Rethrows the current exception; control flow only, not an external input primitive and not a command execution API."
        }
    },
    {
        "__gmon_start__": {
            "type": "neither",
            "reason": "gmon profiling initialization hook; unrelated to external input and OS command execution."
        }
    },
    {
        "__gxx_personality_v0": {
            "type": "neither",
            "reason": "GCC C++ exception personality function; participates in unwinding decisions but is not an input source or command execution sink."
        }
    },
    {
        "__isoc99_sscanf": {
            "type": "neither",
            "reason": "Parses data from an already existing memory string into variables; does not directly cross a process boundary and does not execute commands, so for CWE-78 it is neither source nor sink."
        }
    },
    {
        "__isoc99_swscanf": {
            "type": "neither",
            "reason": "Wide character swscanf variant; parses from an in memory wide string and does not execute commands or act as an external input boundary for CWE-78."
        }
    },
    {
        "__libc_start_main": {
            "type": "neither",
            "reason": "C runtime entry point helper that calls main and initialization functions; not an external input source and not a command execution sink."
        }
    },
    {
        "__stack_chk_fail": {
            "type": "neither",
            "reason": "Stack protector failure handler; indicates corruption and terminates, but does not read external input or execute OS commands."
        }
    },
    {
        "execl": {
            "type": "sink",
            "reason": "Part of the exec family; replaces the current process image with a new program specified by path and arguments. If path or arguments are tainted by attacker controlled data, this is an OS command execution sink for CWE-78."
        }
    },
    {
        "execlp": {
            "type": "sink",
            "reason": "Executes a program by searching it in PATH and passing arguments. When file or arguments are influenced by untrusted input or PATH is attacker controlled, this is a classic command execution sink."
        }
    },
    {
        "exit": {
            "type": "neither",
            "reason": "Terminates the process with a given status code; it does not execute arbitrary commands and is not an external input source."
        }
    },
    {
        "fclose": {
            "type": "neither",
            "reason": "Closes a FILE stream; no external input is read and no OS command is invoked."
        }
    },
    {
        "fgets": {
            "type": "source",
            "reason": "Reads characters from a FILE stream (such as stdin or a file) into a buffer, introducing external or user controlled data into program memory. For CWE-78 it is a typical taint source for command strings or arguments."
        }
    },
    {
        "fopen": {
            "type": "neither",
            "reason": "Opens a file and returns a FILE pointer; while it may be passed a filename derived from external input, it does not itself read file content or execute commands."
        }
    },
    {
        "getenv": {
            "type": "source",
            "reason": "Returns the value of an environment variable. Environment variables can be influenced by external actors; therefore getenv is a standard source of potentially attacker controlled data in CWE-78."
        }
    },
    {
        "iswxdigit": {
            "type": "neither",
            "reason": "Wide character classification routine; inspects a value but does not read from external interfaces or execute OS commands."
        }
    },
    {
        "memmove": {
            "type": "neither",
            "reason": "Performs a memory copy with overlap handling; it only moves data already in memory and does not cross process boundaries or execute commands, so it is neither source nor sink for CWE-78."
        }
    },
    {
        "pclose": {
            "type": "neither",
            "reason": "Closes a stream returned by popen and waits for the associated process to terminate. It does not accept a command string and is not a primary command execution sink."
        }
    },
    {
        "popen": {
            "type": "sink",
            "reason": "Runs a command via the shell and returns a stream connected to its standard input or output. The command parameter is passed to a shell (such as /bin/sh -c), so when it contains unsanitized external data it forms a classic OS command injection sink."
        }
    },
    {
        "printf": {
            "type": "neither",
            "reason": "Formats and prints data to stdout; does not launch OS commands and is not an external input boundary. It is more relevant to format string issues than to CWE-78."
        }
    },
    {
        "puts": {
            "type": "neither",
            "reason": "Writes a string to stdout followed by a newline; it does not execute commands or read external input."
        }
    },
    {
        "rand": {
            "type": "neither",
            "reason": "Returns a pseudo random integer; its output is not attacker controlled in the typical CWE-78 model and it does not execute commands."
        }
    },
    {
        "srand": {
            "type": "neither",
            "reason": "Seeds the pseudo random number generator with an integer; it does not read external input or execute OS commands."
        }
    },
    {
        "strlen": {
            "type": "neither",
            "reason": "Computes the length of a string in memory; purely reads memory and does not cross process boundaries or execute commands."
        }
    },
    {
        "strncat": {
            "type": "neither",
            "reason": "Concatenates at most n characters from src to dest; string manipulation only. It may be used when constructing a command string, but by itself it is not a command execution sink or an external source for CWE-78."
        }
    },
    {
        "system": {
            "type": "sink",
            "reason": "Passes the command string to the system shell (typically equivalent to /bin/sh -c command). If command contains unsanitized attacker controlled data, this is a direct OS command execution sink and the core API for CWE-78."
        }
    },
    {
        "time": {
            "type": "neither",
            "reason": "Returns the current calendar time; this value is not attacker controlled for CWE-78 purposes and does not involve command execution."
        }
    },
    {
        "wprintf": {
            "type": "neither",
            "reason": "Wide character formatted output to stdout; does not execute OS commands and is not an external input source."
        }
    }
]



cwe134_api_ans_cache = [
    {
        "_ITM_deregisterTMCloneTable": {
            "type": "neither",
            "reason": "GCC transactional memory runtime symbol; it does not ingest external input and does not perform any format-string parsing."
        }
    },
    {
        "_ITM_registerTMCloneTable": {
            "type": "neither",
            "reason": "GCC transactional memory runtime symbol; it is unrelated to external input boundaries or format-string interpretation."
        }
    },
    {
        "_Unwind_Resume": {
            "type": "neither",
            "reason": "GCC/C++ exception unwinding helper; it only controls stack unwinding and does not read external input or process format strings."
        }
    },
    {
        "_ZNSt8__detail15_List_node_base7_M_hookEPS0_": {
            "type": "neither",
            "reason": "libstdc++ list internal node hook; it manipulates container metadata only and is not an input source or format-string sink."
        }
    },
    {
        "_ZSt17__throw_bad_allocv": {
            "type": "neither",
            "reason": "Throws std::bad_alloc; it is used for error signaling and does not acquire external data or interpret format strings."
        }
    },
    {
        "_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base": {
            "type": "neither",
            "reason": "libstdc++ red-black tree iterator helper; it operates on internal node pointers and has no interaction with external input or format strings."
        }
    },
    {
        "_ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base": {
            "type": "neither",
            "reason": "libstdc++ red-black tree iterator helper; it is used for data structure traversal and not for external input acquisition or format-string processing."
        }
    },
    {
        "_ZSt20__throw_length_errorPKc": {
            "type": "neither",
            "reason": "Throws std::length_error; this is exception signaling and does not read external input or interpret format strings."
        }
    },
    {
        "_ZSt28__throw_bad_array_new_lengthv": {
            "type": "neither",
            "reason": "Throws bad_array_new_length; it is part of exception handling and is not an input source or format-string sink."
        }
    },
    {
        "_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_": {
            "type": "neither",
            "reason": "libstdc++ red-black tree insertion and rebalancing; it updates container internals and does not take external input or parse format strings."
        }
    },
    {
        "_ZTVN10__cxxabiv117__class_type_infoE": {
            "type": "neither",
            "reason": "C++ RTTI vtable symbol; it represents type metadata only and has no format-string or input semantics."
        }
    },
    {
        "_ZTVN10__cxxabiv120__si_class_type_infoE": {
            "type": "neither",
            "reason": "C++ RTTI vtable symbol for single inheritance type_info; it is metadata and not an input source or format-string sink."
        }
    },
    {
        "_ZdlPvm": {
            "type": "neither",
            "reason": "C++ sized operator delete(void *, size_t); it deallocates memory but does not read external input or interpret format strings."
        }
    },
    {
        "_Znwm": {
            "type": "neither",
            "reason": "C++ operator new(size_t); it allocates memory only and has no external-input or format-string semantics."
        }
    },
    {
        "__ctype_b_loc": {
            "type": "neither",
            "reason": "Returns a pointer to the ctype classification table; it accesses locale metadata and does not act as an input source or format-string sink."
        }
    },
    {
        "__cxa_begin_catch": {
            "type": "neither",
            "reason": "C++ exception handling runtime function; it manages exception state and does not process external input or format strings."
        }
    },
    {
        "__cxa_end_catch": {
            "type": "neither",
            "reason": "C++ exception handling runtime function; it ends a catch block and does not parse format strings or import external data."
        }
    },
    {
        "__cxa_finalize": {
            "type": "neither",
            "reason": "Finalizer dispatcher invoked at exit or shared object unload; it calls destructors but does not read external input or interpret format strings."
        }
    },
    {
        "__cxa_pure_virtual": {
            "type": "neither",
            "reason": "Handler for pure virtual function calls; it typically aborts the program and is not an input source or format-string sink."
        }
    },
    {
        "__cxa_rethrow": {
            "type": "neither",
            "reason": "Re-throws the current exception; this is control-flow only and involves no external input or format-string processing."
        }
    },
    {
        "__gmon_start__": {
            "type": "neither",
            "reason": "gmon profiling initialization hook; it is related to profiling and has no external-input or format-string role."
        }
    },
    {
        "__gxx_personality_v0": {
            "type": "neither",
            "reason": "GCC C++ exception personality function; it participates in unwinding but does not acquire external data or interpret format strings."
        }
    },

    {
        "__isoc99_sscanf": {
            "type": "sink",
            "reason": "sscanf(const char *s, const char *format, ...) parses a format string and consumes variadic arguments. If the format string is attacker-controlled, this can cause uncontrolled format-string behavior, including stack reading and potential misuse of %n. Therefore, for CWE-134 it is a format-string sink."
        }
    },
    {
        "__isoc99_swscanf": {
            "type": "sink",
            "reason": "swscanf(const wchar_t *s, const wchar_t *format, ...) is the wide-character analogue of sscanf. It interprets the format string and uses variadic arguments. An attacker-controlled format string can cause uncontrolled format-string behavior. It is a CWE-134 sink."
        }
    },

    {
        "__libc_start_main": {
            "type": "neither",
            "reason": "glibc process entry helper; it calls main and init/fini functions but does not itself read external input or interpret format strings."
        }
    },
    {
        "__stack_chk_fail": {
            "type": "neither",
            "reason": "Stack canary failure handler; it indicates stack corruption and usually terminates the process, but it is not an input source or format-string sink."
        }
    },

    {
        "accept": {
            "type": "neither",
            "reason": "Accepts a new network connection and returns a socket descriptor. It does not read application-level data or interpret format strings, so it is neither source nor sink for CWE-134."
        }
    },
    {
        "bind": {
            "type": "neither",
            "reason": "Binds a socket to a local address; it does not bring in external payload data and does not process format strings."
        }
    },
    {
        "close": {
            "type": "neither",
            "reason": "Closes a file descriptor; it is a resource-management call with no external-input or format-string semantics."
        }
    },
    {
        "connect": {
            "type": "neither",
            "reason": "Establishes a connection for a socket; it does not read external data and does not interpret format strings."
        }
    },
    {
        "fclose": {
            "type": "neither",
            "reason": "Closes a FILE stream; it does not acquire external input or parse format strings."
        }
    },
    {
        "fgets": {
            "type": "source",
            "reason": "Reads bytes from a FILE* stream (such as stdin, files, or pipes) into a buffer. The resulting string is typically attacker-controlled in many threat models and may later be used as a format string, so it is a classic taint source for CWE-134."
        }
    },
    {
        "fopen": {
            "type": "neither",
            "reason": "Opens a file and returns a FILE* handle; it does not itself read file contents or interpret format strings."
        }
    },
    {
        "fprintf": {
            "type": "sink",
            "reason": "fprintf(FILE *stream, const char *format, ...) interprets a format string and uses variadic arguments. If the format string is attacker-controlled, this directly leads to uncontrolled format-string vulnerabilities (e.g., information disclosure or %n-based writes). It is a CWE-134 sink."
        }
    },
    {
        "getenv": {
            "type": "source",
            "reason": "Returns the value of an environment variable as a string. Environment variables can be influenced by external actors; if such a string is later used as a format string, it can cause CWE-134, so getenv is a taint source."
        }
    },
    {
        "htons": {
            "type": "neither",
            "reason": "Converts a 16-bit value from host to network byte order; it is a pure numeric conversion and has no format-string or external-input implications."
        }
    },
    {
        "inet_addr": {
            "type": "neither",
            "reason": "Parses a dotted-decimal IPv4 string into a numeric address; it reads an in-memory string and does not involve variadic arguments or format-string interpretation."
        }
    },
    {
        "iswxdigit": {
            "type": "neither",
            "reason": "Wide-character classification function; it inspects a character but does not serve as an external input boundary or a format-string sink."
        }
    },
    {
        "listen": {
            "type": "neither",
            "reason": "Marks a socket as passive for accepting connections; it does not read application data and does not interpret format strings."
        }
    },
    {
        "memmove": {
            "type": "neither",
            "reason": "Copies a block of memory, allowing overlap; it only moves existing in-memory data and does not directly handle external input or format strings (although it can propagate taint)."
        }
    },
    {
        "memset": {
            "type": "neither",
            "reason": "Fills a block of memory with a byte value; it neither introduces external input nor interprets format strings."
        }
    },
    {
        "printf": {
            "type": "sink",
            "reason": "printf(const char *format, ...) interprets a format string and consumes variadic arguments. If the format string is attacker-controlled, this is the textbook uncontrolled format-string sink (e.g., stack disclosure, %n writes). It is a core CWE-134 sink."
        }
    },
    {
        "puts": {
            "type": "neither",
            "reason": "puts(const char *s) writes a string to stdout followed by a newline without interpreting % sequences as format specifiers. It does not perform format-string parsing, so it is neither source nor sink for CWE-134."
        }
    },
    {
        "rand": {
            "type": "neither",
            "reason": "Returns a pseudo-random integer. It does not accept external input and does not process format strings."
        }
    },
    {
        "recv": {
            "type": "source",
            "reason": "Reads raw bytes from a socket into a buffer. The received data is controlled by the remote peer and is a primary external-input boundary; if such data is later used as a format string, it can cause CWE-134. Therefore, recv is a source."
        }
    },
    {
        "snprintf": {
            "type": "sink",
            "reason": "snprintf(char *s, size_t maxlen, const char *format, ...) interprets the format string and uses variadic arguments. Even though it bounds the output length, an attacker-controlled format string still triggers uncontrolled format-string behavior. It is a CWE-134 sink."
        }
    },
    {
        "socket": {
            "type": "neither",
            "reason": "Creates a socket descriptor; it does not read data from external entities and does not interpret format strings."
        }
    },
    {
        "srand": {
            "type": "neither",
            "reason": "Seeds the pseudo-random number generator; it does not bring in attacker-controlled strings and does not parse format strings."
        }
    },
    {
        "strchr": {
            "type": "neither",
            "reason": "Searches for a character in a string; it only reads existing memory and has no format-string semantics."
        }
    },
    {
        "strlen": {
            "type": "neither",
            "reason": "Computes the length of a string; it is a read-only operation on memory, not an external-input or format-string function."
        }
    },
    {
        "strncat": {
            "type": "neither",
            "reason": "Concatenates at most n characters from src to dest; it is a string construction/propagation function and does not itself interpret format strings or cross input boundaries."
        }
    },
    {
        "time": {
            "type": "neither",
            "reason": "Returns the current time; this value is not attacker-controlled in the typical CWE-134 model and does not involve format-string processing."
        }
    },
    {
        "vfprintf": {
            "type": "sink",
            "reason": "vfprintf(FILE *s, const char *format, va_list arg) interprets a format string using a va_list. If the format string is attacker-controlled, this is an uncontrolled format-string sink with the usual risks (stack disclosure, %n writes, crashes)."
        }
    },
    {
        "vprintf": {
            "type": "sink",
            "reason": "vprintf(const char *format, va_list arg) is the va_list-based variant of printf; it interprets the format string from a va_list. An attacker-controlled format string makes it a classic CWE-134 sink."
        }
    },
    {
        "wprintf": {
            "type": "sink",
            "reason": "wprintf(const wchar_t *format, ...) is the wide-character formatted output function. It interprets a wide-character format string with variadic arguments. If the format string is attacker-controlled, this causes uncontrolled format-string behavior, so it is a CWE-134 sink."
        }
    }
]



both_reason_str="The call chain consists only of the API's caller; in other words, the API acts as both the source and the sink. Because a vulnerability may be triggered at the moment data is read, our analysis of potential issues focuses solely on this API's invocation within that caller."



