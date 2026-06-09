# Polonium Mapper
When I first started digging into the Lenovo Diagnostics Driver, I didn't expect to find a complete kernel exploitation primitive sitting in a signed driver. But after a few hours of reversing with IDA it became clear that this driver was essentially a kernel mode read/write primitive waiting to be abused.

## discovery: Finding the Vulnerability

I put the Lenovo sys into IDA Pro. The driver registers a device at `\\.\LenovoDiagnosticsDriver`, so I knew I was looking for `IRP_MJ_DEVICE_CONTROL` handlers. After tracing through the dispatch routines, I found three IOCTLs that stood out immediately:

- **0x222010** - Physical memory read
- **0x222014** - Physical memory write  
- **0x222000** - Function calling (this one was interesting)

The driver was taking physical addresses directly from user input without any validation. No checks for kernel space, no checks for MMIO regions - nothing. I verified this by writing a quick test program that tried to read physical address `0x1000`, and it worked. That was the moment I realized I had arbitrary physical memory access.
```

## The Hard Part: Virtual to Physical Translation

Having physical read/write is great, but Windows uses virtual addressing. I needed a way to translate virtual addresses to physical ones to actually do anything useful in the kernel.

I spent a solid weekend reverse engineering the page table walking code in `ntoskrnl.exe`. The key function is `MiGetPteAddress`, but here's the catch: **the offset changes with every Windows build**. I was originally hardcoding offsets for my test machine (Win10 22H2), but the moment I tested on a different build, everything broke.

The solution was calculating the PTE base dynamically. I found that `MiGetPteAddress` contains a constant that points to the base of the page tables. By reading from a specific offset in that function, I could get `PteBase`, then calculate the hierarchy myself:

```cpp
// This was the breakthrough - calculating PTE addresses manually
UINT64 CreatePteHierarchy(UINT64 VirtualAddress) {
    // Shift and mask magic derived from Intel manuals + reversing MiGetPteAddress
    VirtualAddress >>= 9;
    VirtualAddress &= 0x7FFFFFFFF8;
    return VirtualAddress + PteBase;
}
```

## The Shellcode Injection Trick

Now I could read and write physical memory, but I needed a way to call arbitrary kernel functions. I couldn't just overwrite kernel code 

The trick was finding a safe place to inject shellcode. I discovered that the Lenovo driver itself has a `.data` section that's marked RWX (Read-Write-Execute) in physical memory. Even better, I could modify the page tables to make any page writable, inject my shellcode, then restore the permissions.

I wrote a small x64 assembly trampoline that acts as a universal function caller:

```asm
; Injected at offset 0x1200 in the driver
mov rax, [rcx+18h]      ; Get function pointer from structure
mov rcx, [rsp+28h]      ; Arg1
mov rdx, [rsp+30h]      ; Arg2
mov r8,  [rsp+38h]      ; Arg3  
mov r9,  [rsp+40h]      ; Arg4
call rax
mov rcx, [rsp+48h]      ; Result pointer
mov [rcx], rax          ; Store return value
ret
```

The shellcode parses the `CALL_DATA` structure I pass in via IOCTL 0x222000, sets up the registers according to the Windows x64 calling convention, calls the function, and stores the result. This effectively turns the Lenovo driver into a universal kernel function caller.

## Why I Implemented PDB Parsing

Initially, I had a header file full of hardcoded offsets like this:

```cpp
#define OFFSET_EPROCESS_LINKS 0x448
#define OFFSET_EPROCESS_PID 0x440
// ...
```

But every time Windows updated, these changed, and the tool would crash or return garbage. I got tired of manually updating offsets for every build.

I decided to implement a PDB parser using the DbgHelp API. Now the tool:
1. Downloads the correct PDB for your specific `ntoskrnl.exe` from Microsoft's symbol server
2. Parses structure offsets at runtime (like `_EPROCESS.ActiveProcessLinks`)
3. Resolves function RVAs (like `MiGetPteAddress`)

## Manual Driver Mapping: The Final Piece

With arbitrary kernel function execution working, the next step was loading my own unsigned drivers.

The process I implemented is essentially a kernel-mode PE loader:

1. **Allocate memory**: Call `MmAllocateIndependentPages` (a kernel API that allocates non-paged memory outside the standard pool tracking)
2. **Copy sections**: Parse the PE headers and map sections into kernel space
3. **Fix relocations**: Adjust pointers for the new base address (handling `IMAGE_REL_BASED_DIR64`)
4. **Resolve imports**: Walk the IAT and patch in addresses from `ntoskrnl.exe` exports
5. **Set permissions**: Use `MmSetPageProtection` to mark code sections as executable
6. **Call entry**: Invoke `DriverEntry` with the mapped base address

The import resolution was tricky because some drivers import by ordinal. I ended up only supporting imports by name for simplicity, but for most drivers, that's sufficient.

## The PreviousMode Bypass

One subtle issue I ran into: when calling kernel functions from user-mode, Windows checks `PreviousMode` in the `_KTHREAD` structure to see if the call originated from user space. Some kernel functions behave differently (or fail) when called from user-mode.

I reverse engineered the `_KTHREAD` structure to find the `PreviousMode` field (offset 0x232 on most builds). Before calling sensitive functions, my tool:
1. Finds the current thread's `_ETHREAD` via the `ThreadListHead` in `_EPROCESS`
2. Sets `PreviousMode` to 0 (KernelMode)
3. Executes the function
4. Restores it to 1 (UserMode)

This bypasses checks that would otherwise prevent certain operations from user-space initiated calls.

The manual driver mapping is essentially rootkit-level functionality, but achieved through a legitimate signed driver. That's the reality of BYOVD attacks you're using the system's trust in signed code against itself.
