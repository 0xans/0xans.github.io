# MirrorGate: Abusing Console APIs for indirect Memory Injection.
The project can be found here on my [GitHub](https://github.com/0xans/Mirror-Gate)

### Introduction

We all know the drill. The holy trinity of process injection has been beaten to death: `OpenProcess`, `WriteProcessMemory`, `CreateRemoteThread`. Every single EDR on earth has these API calls hooked, tagged and begged. If you run that sequence today, you are lighting up the SOC dashboard. 

I wanted to break that chain. Specifically, I wanted to find a way to write data into remote process **without** using `WriteProcessMemory` or `NtWriteVirtualMemory`.

This is a POC implementation in Rust that abuses the windows console subsystem to reflect data from one process into another. By attaching to a target console and hijacking its threads, we can force that process to pull the shellcode rather than push it.

### The Theory: Reflected write primitives.

The core idea came from a write-up I stumbled across a while back. The concept was inspired by an article I came across previously. If you recognize the original source, please contact me so I can credit it properly, but they were discussing some niche abuse of console buffers for data exchange. That got me thinking: if two processes are already sharing the console window, what specific API calls act as the bridge?

There is an API called `SetConsoleTitleA` which sets the text at the top of the CMD window. There is a corresponding API called `GetConsoleTitleA` which retrieves it.

Here is the logic path I traced:

1. **Shared Resource**: If I use `AttachConsole`, my process and the target process share the same console window
2. **The Staging Area**: If I call `SetConsoleTitleA` in *my* process, the string is stored in the console subsystem (CSRSS/Conhost).
3. **The Trigger**: If I can force the *target* process to call `GetConsoleTitleA`, it will read that string (my shellcode) from the subsystem and write it into its own memory.

We are essentially using the console window title as a shared buffer to smuggle the shellcode chunk by chunk.

### The Implementation.

I chose **Rust** for this because I love this language and for it’s direct control over memory and C-interop via `winapi`. Let’s break down the code block by block.

1. **Setup and Macros.**

We start with standard `winapi` imports. I am using a few custom macros (`OKAY!`, `INFO!`, `EROR!`) to keep the console output clean and readable during debugging.

```rust
 /*----------[MACROS]----------*/
macro_rules! OKAY {($($arg:tt)*) => {println!("[+] {}", format_args!($($arg)*))};}
// ... (Logging macros)

macro_rules! CTXT {
    ($ctx:expr) => {
        println!("\n[ ----- REGISTERS -----]");
        println!(" | RSP - 0x{:016x}", $ctx.Rsp);
        println!(" | RIP - 0x{:016x}", $ctx.Rip);
        // ...
    };
}
```

The `CTXT!` macro is particularly useful here because we are going to be modifying the CPU registers manually, and we need to verify they are set correctly.

1. **The `MirrorGate` Function (Core).**

This is the heart of the code. Instead of `WriteProcessMemory`, we define a function called `MirrorGate`.

**How it works:**

1. **Suspend**: We pause the target thread using `SuspendThread`.
2. **Context**: We grab the thread’s current state (registers) using `GetThreadContext`.
3. **Stage Data:** We call `SetConsoleTitleA` in our injector process. This puts our payload chunks into the window title.
4. **Hijack**: We modify the target thread’s context:
    1. **RIP (Instruction Pointer)**: Pointed to `GetConsoleTitleA`. When the thread wakes up, it executes this function.
    2. **RCX (First Argument)**: Pointed to the destination memory address in the target process.
    3. **RDX (Second Argument)**: The size of the payload 
    4. **RSP (Stack Pointer)**: We set this to a return address to maintain stability.
5. **Resume: We call `ResumeThread`.**

The target thread wakes up, thinks it needs to run `GetConsoleTitleA`, pulls our payload from the window title, write it to `RCX`, and then we sleep for 250ms to let it finish.

```rust
fn MirrorGate(hThread: HANDLE, Rip: LPVOID, RetAddr: LPVOID, DestAddr: LPVOID, SrcBuff: LPBYTE , BufSize: SIZE_T) -> Result<(), ()> {
    unsafe {
        if SuspendThread(hThread) == u32::MAX { /* Error Handling */ }
        
        // ... Get Context ...

        // 1. Hijack the Registers (x64 Calling Convention)
        ctx.Rsp = RetAddr as u64;
        ctx.Rip = Rip as u64;        // Function to run (GetConsoleTitleA)
        ctx.Rcx = DestAddr as u64;   // Arg1: Where to write the data
        ctx.Rdx = BufSize as u64;    // Arg2: How much data

        if SetThreadContext(hThread, &ctx) == 0 { /* Error Handling */ }

        // 2. Stage the payload in the Console Title
        if SetConsoleTitleA(SrcBuff as *const i8) == 0 { /* Error Handling */ }

        // 3. Let the target run
        if ResumeThread(hThread) == u32::MAX { /* Error Handling */ }
        
        Sleep(250); // Wait for execution
    }
    Ok(())
}
```

1. **The `main` Loop: Connecting the Dots.**

The main function handles the logistics.

First, we attach to the target process and allocate memory. Note that we still use `VirtualAllocEx`. While this is a flagged API, the specific “write” behavior is usually the stronger indicator of malicious intent that the allocation itself.

```rust
// Attach to target console
OKAY!("Detaching console..");
FreeConsole(); // Drop our own console
if AttachConsole(pid) == 0 { // Hook into the target's console
    EROR!("AttachConsole", GetLastError());
    exit(1)
}
```

*Critical Note:* This is why MirrorGate only works on **Console Applications** (like `cmd.exe` or `conhost.exe`). If the target process does not have a console to attach to, `AttachConsole` fails, and the mirror breaks.

1. **Resolving Addresses.**

We need to know where `GetConsoleTitleA` lives. Since system DLLs (like `kernalbase.dll`) are usually loaded at the same base address in all processes (thanks to ASLR optimizations), we can find the address in our process and assume it’s the same in the target.

```rust
let hKernelBase = GetModuleHandleA(b"kernelbase.dll\0".as_ptr() as *const i8);
let fGetConsoleTitleA = GetProcAddress(hKernelBase, b"GetConsoleTitleA\0".as_ptr() as *const i8);
```

1. **The Injection Sequence.**

We don’t just write the shellcode. We perform a precise dance to ensure execution flow.

1. **Write Loop Address**: We write a loop address to keep thread stable.
2. **Write Payload Pointer**: We write the pointer where out shellcode will live.
3. **Write Shellcode:** We execute the `MirrorGate` function to copy the actual `PopCalc` shellcode.

```rust
// Writing the Shellcode using the "Mirror" technique
if MirrorGate(
    hThread,
    fGetConsoleTitleA,
    (buffer as ULONG_PTR + 0x7010) as LPVOID, // Return address
    (buffer as ULONG_PTR + 0x7020) as LPVOID, // Destination
    PAYLOAD.as_mut_ptr(),                     // Source (Our local array)
    PAYLOAD.len()                             // Size
).is_err() {
    // ...
}
```

### Pros and Cons.

No technique is perfect. Here is the operational assessment of MirrorGate.

**(+) Pros:**

- **Bypasses `WriteProcessMemory`**: We completely avoid the most monitored API for injection.
- **Legitimate API Traffic**: `GetConsoleTitleA` is a benign API. Seeing a console apps querying their own title is rarely flagged as malicious.
- **Harder to Hook**: Security products usually hook memory writes. They rarely hook “Get Window Title” because it generates too much noise.

**(-) Cons:**

- **Target Limitation**: This **only** works on programs running in the Windows Command Prompt / Windows Subsystem. You cannot use this to inject into `notepad.exe` or `explorer.exe` because they don’t have a standard console to attach to.
- **Speed:** Because we have to sleep between context switches to ensure the thread executes the instructions, injection is slower than direct memory writing.
- **Visible Artifacts**: If a user is staring at the window title bar of the target process, they might see the title flicker of change to garbage text (our shellcode) for a split second.

### Conclusion.

MirrorGate demonstrates that you don’t need administrative write primitive to move code between processes. By understanding how Windows manages shared resources — like the Console Window — we can turn the operating system’s own feature into a transport mechanism for our payload.

The code provides a template. The next step? Finding other shared resources (Clipboard? Named Pipes? Environment Variables?) to achieve the same result without the console limitation.

*Stay dangerous*.
