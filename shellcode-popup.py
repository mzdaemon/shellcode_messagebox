import ctypes, struct
from keystone import *

CODE = (
    " start:                            " #
    #"   int3                           ;" # Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov ebp, esp                   ;" #

    " find_kernel32:                   "
    "   xor ecx, ecx                   ;" # // ECX = 0
    "   mov eax, fs:[ecx + 0x30]       ;" # // EAX = PEB
    "   mov eax, [eax + 0xc]           ;" # // EAX = PEB -> Ldr 
    "   mov esi, [eax + 0x14]          ;" # // ESI = PEB -> Ldr.InMemoryOrderModuleList -> has a pointer to _LIST_ENTRY structure with Flink and BLINk double liked list 
    "   lodsd                          ;" # // EAX = Second module // lodsd will store ESI pointer of Flink value in EAX and increment ESI to next pointer.
    "   xchg eax, esi                  ;" # // EAX <=> ESI // will exchange values of _LDR_DATA_TABLE_ENTRY structure, esi will receive the pointer of the LDR DATA TABLE ENTRY from eax .
    "   lodsd                          ;" # // EAX = Third(kernel32) after lodsd stores next pointer of _LDR_DATA_TABLE_ENTRY from ESI in EAX
    "   mov ebx, [eax + 0x10]          ;" # // EBX (kenerl32) = [eax+0x10] => Kernel32 base address
    "   mov edx, [ebx + 0x3c]          ;" # EDX = DOS -> e_lfanew
    "   add edx, ebx                   ;" # EDX = PE Header
    "   mov edx, [edx + 0x78]          ;" # EDX = Offset Export Table Directory RVA
    "   add edx, ebx                   ;" # EDX = Export Table Directory VMA
    "   mov esi, [edx + 0x20]          ;" # ESI = AddressOfNames RVA
    "   add esi, ebx                   ;" # ESI = AddressOfNames VMA
    "   xor ecx, ecx                   ;" # ECX = 0

    " find_function:                     "
    "   inc ecx                         ;" # ECX -> counter for array index
    "   lodsd                           ;" # lodsd will store ESI pointer of AddressOfName value in EAX and increment ESI to next pointer.
    "   add eax, ebx                    ;" # VMA of function name
    "   cmp dword ptr[eax], 0x50746547  ;" # compare functioname with string GetP
    "   jnz find_function               ;" # jump to find_function if doesn't match
    "   cmp dword ptr[eax+4],0x41636f72 ;" # compare functioname with string rocA
    "   jnz find_function               ;" # jump to find_function if doesn't match
    "   cmp dword ptr[eax+8],0x65726464 ;" # compare functioname with string ddre
    "   jnz find_function               ;" # jump to find_function if doesn't match
    "   mov esi, [edx + 0x24]           ;" # AddressOfNameOrdinals RVA 
    "   add esi, ebx                    ;" # AddressOfNameOrdinals VMA
    "   mov cx, [esi + 2 * ecx]         ;" # Extrapolate the AddressOfNameOrdinals
    "   dec ecx                         ;" # ECX = -1
    "   mov esi, [edx + 0x1c]           ;" # ESI = AddressOfFunction RVA
    "   add esi, ebx                    ;" # ESI = AddressOfFunctions VMA
    "   mov edx, [esi + ecx * 4]        ;" # Get the function RVA
    "   add edx, ebx                    ;" # Get the function VMA
    "   mov [ebp], ebx                  ;" # [EBP] = kernel32 base address
    "   mov [ebp + 4], edx              ;" # [EBP+4] = GetProcAddressStub

    " TerminateProcess:                  "
    "   xor ecx, ecx                    ;" # ECX = 0
    "   push ecx                        ;" # 0 onto the stack
    "   push 0x73736563                 ;" # cess
    "   push 0x6f725065                 ;" # ePro
    "   push 0x74616e69                 ;" # inat
    "   push 0x6d726554                 ;" # Term
    "   push esp                        ;" # pushes a pointer to TerminateProcess string onto the stack
    "   push [ebp]                      ;" # pushes [ebp] = kernel32 base address onto the stack
    "   call [ebp + 4]                  ;" # Call [EBP+4] = GetProcAddressStub
    "   mov esi, eax                    ;" #   esi = eax -> Save TerminateProcess for later use

    " LoadLibraryA:                    "
    "   xor ecx, ecx                    ;" # ECX = 0
    "   push ecx                        ;" # 0 onto the stack
    "   push 0x41797261                 ;" # aryA
    "   push 0x7262694c                 ;" # Libr
    "   push 0x64616f4c                 ;" # Load
    "   push esp                        ;" # pushes a pointer to LoadLibraryA string onto the stack
    "   push [ebp]                      ;" # pushes [ebp] = kernel32 base address onto the stack
    "   call [ebp + 4]                  ;" # Call [EBP+4] = GetProcAddressStub
    "   mov [ebp+8], eax                ;" # [EBP+8] = eax -> LoadLibraryAStub

    " user32.dll_load:                  "
    "   xor ecx, ecx                    ;" # ECX = 0
    "   push ecx                        ;" # 0 onto the stack
    "   mov cx, 0x6c6c                  ;" # ll
    "   push ecx                        ;" # ll
    "   push 0x642e3233                 ;" # 32.d
    "   push 0x72657375                 ;" # user
    "   push esp                        ;" # pushes a pointer to user32.dll string onto the stack
    "   call [ebp + 8]                  ;" # Call [EBP+8] = LoadLibraryAStub
    "   mov [ebp+0xc], eax              ;" # [EBP+0xc] = eax -> user32.dll

    " Advapi32.dll_load:                  "
    "   xor ecx, ecx                    ;" # ECX = 0
    "   push ecx                        ;" # 0 onto the stack
    "   push 0x6c6c642e                 ;" # .dll
    "   push 0x32336970                 ;" # pi32
    "   push 0x61766441                 ;" # Adva
    "   push esp                        ;" # pushes a pointer to Advapi32.dll string onto the stack
    "   call [ebp + 8]                  ;" # Call [EBP+8] = LoadLibraryAStub
    "   mov [ebp+0x10], eax             ;" # [EBP+0x10] = eax -> Advapi32.dll

    " GetUserNameA:                      "
    "   push ecx                        ;" # 0 onto the stack
    "   push 0x41656d61                 ;" # ameA
    "   push 0x4e726573                 ;" # serN
    "   push 0x55746547                 ;" # GetU
    "   push esp                        ;" # pushes a pointer to GetUserNameA string onto the stack
    "   push [ebp+0x10]                 ;" # module address [EBP+0x10] = eax -> Advapi32.dll
    "   call [ebp + 4]                  ;" # Call [EBP+4] = GetProcAddressStub
    "   mov [ebp+0x14], eax             ;" # [EBP+0x14] = eax -> GetUserNameA

    " MessageBoxA:                      "
    "   xor ecx, ecx                    ;" # ECX = 0
    "   push ecx                        ;" # 0 onto the stack
    "   mov eax, 0xffbe8791             ;" # -0x41786f
    "   neg eax                         ;" #
    "   push eax                        ;" # oxA
    "   push 0x42656761                 ;" # ageB
    "   push 0x7373654d                 ;" # Mess
    "   push esp                        ;" # pushes a pointer to MessaBoxA string onto the stack
    "   push [ebp+0xc]                  ;" # module address [EBP+0xc] = eax -> user32.dll
    "   call [ebp + 4]                  ;" # Call [EBP+4] = GetProcAddressStub
    "   mov ebx, eax                     ;" # ebx = eax -> MessageBoxA

    " GetUserName:                      "
    "   sub esp, 0xfffffefc             ;" # Add some space on the stack for lpBuffer
    "   xor ecx, ecx                    ;" # ECX = 0
    "   push esp                        ;" #  lpBuffer
    "   pop eax                         ;" #  EAX = lpBuffer
    "   mov edi, eax                    ;" # EDI = lpBuffer // Save lpBuffer for later to be used in MessageBox
    "   mov cx, 0x20                    ;" # Size for the string
    "   push ecx                        ;" # pushes ecx onto stack
    "   push esp                        ;" # lpBuffer (size of the string)
    "   push eax                        ;" # lpBuffer
    "   call [ebp+0x14]                 ;" # call [ebp+14] = GetUserNameA

    " CallMessageBox:                    "
    "   xor ecx, ecx                    ;" # ECX = 0
    "   push ecx                        ;" # NULL
    "   push 0x21212121                  ;" #  !!!!
    "   push 0x74736554                  ;" #  Test
    "   mov edx, esp                    ;" # lpCaption
    "   xor ecx, ecx                    ;" # ECX = 0
    "   push ecx                        ;" # uType
    "   push edx                        ;" # lpCaption
    "   push edi                        ;" # lpText
    "   push ecx                        ;" # hWnd
    "   call ebx                        ;" # ebx -> MessageBoxA


    " call_terminateprocess:            "
    "   xor ecx, ecx                    ;" # NULL EAX
    "   push ecx                        ;" # Push dwExitCode
    "   push 0xffffffff                 ;" # Push -1 (hProcess)
    "   call esi                        ;" # Call TerminateProcess
    


)

# Initialize engine x86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                    ctypes.c_int(len(shellcode)),
                                    ctypes.c_int(0x3000),
                                    ctypes.c_int(0x40)
)

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                    buf,
                                    ctypes.c_int(len(shellcode))
)

print("Shellcode Location at address %s" % hex(ptr))
input("..INPUT ENTER TO EXECUTE THE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                    ctypes.c_int(0),
                                    ctypes.c_int(ptr),
                                    ctypes.c_int(0),
                                    ctypes.c_int(0),
                                    ctypes.pointer(ctypes.c_int(0))
)


ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),
                                        ctypes.c_int(-1)
)
