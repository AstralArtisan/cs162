
# Pintos proj1: Userprog

## Table of Contents

- [Pintos proj1: Userprog](#pintos-proj1-userprog)
  - [Argument Passing](#argument-passing)
    - [Virtual Memory](#virtual-memory)
    - [What does a function call do?](#what-does-a-function-call-do)
    - [Program startup](#program-startup)
    - [Implement argument passing](#implement-argument-passing)
  - [Process Control Syscalls](#process-control-syscalls)
    - [What happens when there comes to a system call?](#what-happens-when-there-comes-to-a-system-call)
    - [Accessing user memory safely](#accessing-user-memory-safely)
    - [Building `syscall_handler`](#building-syscall_handler)
      - [Safely reading the system call number and arguments](#safely-reading-the-system-call-number-and-arguments)
      - [Putting it together in `syscall_handler`](#putting-it-together-in-syscall_handler)
    - [Tracking Child Processes: `struct child`](#tracking-child-processes-struct-child)
      - [Motivation](#motivation)
      - [The child structure](#the-child-structure)
      - [Initializing the structure](#initializing-the-structure)
      - [Usage across system calls](#usage-across-system-calls)
    - [Details of syscalls](#details-of-syscalls)
      - [PRACTICE](#practice)
      - [HALT](#halt)
      - [EXIT](#exit)
      - [EXEC](#exec)
      - [WAIT](#wait)
      - [FORK](#fork)
  - [File Operation Syscalls](#file-operation-syscalls)
    - [Synchronization](#synchronization)
    - [Details of syscalls](#details-of-syscalls-1)
      - [CREATE](#create)
      - [REMOVE](#remove)
      - [OPEN](#open)
      - [FILESIZE](#filesize)
      - [READ](#read)
      - [WRITE](#write)
      - [SEEK](#seek)
      - [TELL](#tell)
      - [CLOSE](#close)
    - [Additional work for file operations](#additional-work-for-file-operations)
      - [Close all the files when process exits](#close-all-the-files-when-process-exits)
      - [Denying writes to running executables](#denying-writes-to-running-executables)
      - [`fork` with open files](#fork-with-open-files)
  - [Summary by ChatGPT](#summary-by-chatgpt)


## Argument Passing

At the first time I got such a large project, I didn't know how to deal with it. Through the proj0 and Pintos document, I tried to use `gdb` to debug the program, and learned how does a user program execute.

### Virtual Memory

The first question I tried to understand was: *“What does the virtual address space look like?”*

Pintos splits the virtual address space into two regions: **user** and **kernel**. User space ranges from `0` up to `PHYS_BASE` (`0xc0000000`), and kernel space occupies the rest. The user virtual memory is laid out roughly as follows:

```tex
PHYS_BASE +----------------------------------+
           |            user stack            |
           |                |                 |
           |                |                 |
           |                V                 |
           |           grows downward         |
           |                                  |
           |                                  |
           |                                  |
           |                                  |
           |           grows upward           |
           |                ^                 |
           |                |                 |
           |                |                 |
           +----------------------------------+
           | uninitialized data segment (BSS) |
           +----------------------------------+
           |     initialized data segment     |
           +----------------------------------+
           |           code segment           |
0x08048000 +----------------------------------+
           |                                  |
           |                                  |
           |                                  |
           |                                  |
           |                                  |
         0 +----------------------------------+
```

When implementing the project, it is crucial that a user program only accesses **user** virtual addresses (below `PHYS_BASE`). Kernel threads can access both kernel virtual memory and, when a user process is running, that process’s user virtual memory. However, even in kernel mode, dereferencing an unmapped user address still causes a page fault.

### What does a function call do?

On x86, a normal C function call roughly behaves as follows:

1. The caller pushes each of the function’s arguments on the stack one by one, normally using the `push` x86 instruction.

   Arguments are pushed in right-to-left order. The stack grows downward: each push decrements the stack pointer, then stores into the location it now points to, like the C expression `*(--sp) = value`.

2. The caller pushes the address of its next instruction (the *return address*) on the stack and jumps to the first instruction of the callee. A single 80x86 instruction, `call`, does both.

3. The callee executes. When it takes control, the stack pointer points to the return address, the first argument is just above it, the second argument is just above the first argument, and so on.

4. If the callee has a return value, it stores it into register `eax`.

5. The callee returns by popping the return address from the stack and jumping to the location it specifies, using the 80x86 `ret` instruction.

6. The caller pops the arguments off the stack.

Example: calling `f(1, 2, 3)` :

```tex
                             +----------------+
                  0xbffffe7c |        3       |
                  0xbffffe78 |        2       |
                  0xbffffe74 |        1       |
stack pointer --> 0xbffffe70 | return address |
                             +----------------+
```

A user program “starting up” is essentially just another function call. Therefore, it is important to know what the initial user stack should look like.

### Program startup

In Pintos, a user program starts in a function named `_start`:

```c
void _start (int argc, char *argv[]) {
    exit (main (argc, argv));
}
```

Consider the command line:

```tex
/bin/ls -l foo bar
```

At `PHYS_BASE`, the kernel must set up the initial user stack. Conceptually, it does the following:

1. Push the argument strings `argv[i]` onto the stack from `i = argc - 1` down to `0`.
2. Perform stack alignment.
3. Push the `argv[argc]` null sentinel.
4. Push the pointers `argv[i]` (from `i = argc - 1` down to `0`).
5. Push `argv` itself (a pointer to `argv[0]`).
6. Push `argc`.
7. Push a fake `return` address.

The resulting stack might look like this:

```tex
 Address         Name         Data        Type
0xbffffffc   argv[3][...]    bar\0       char[4]
0xbffffff8   argv[2][...]    foo\0       char[4]
0xbffffff5   argv[1][...]    -l\0        char[3]
0xbfffffed   argv[0][...]    /bin/ls\0   char[8]
0xbfffffec   stack-align       0         uint8_t
0xbfffffe8   argv[4]           0         char *
0xbfffffe4   argv[3]        0xbffffffc   char *
0xbfffffe0   argv[2]        0xbffffff8   char *
0xbfffffdc   argv[1]        0xbffffff5   char *
0xbfffffd8   argv[0]        0xbfffffed   char *
0xbfffffd4   argv           0xbfffffd8   char **
0xbfffffd0   argc              4         int
0xbfffffcc   return address    0         void (*) ()
```

In this example, the initial user stack pointer (`esp`) would be `0xbfffffcc`, and the user stack region starts at `PHYS_BASE`.

### Implement argument passing

To start a user program, we must fix the functions in `process.c` so that the new process is initialized correctly.

- The `process_execute` function creates a new user process. It receives the command line string `file_name` from the kernel command line.
  - We use a `while` loop to extract the `program_name` (the first token).
  - This `program_name` is passed as the new thread name to `thread_create()`.
  - `process_execute` returns the PID (which equals the TID of the main thread of the new process).
- The `start_process` function (the thread function passed to `thread_create`) loads the user process and starts it running.
  - It first splits the command line into `argv` using `strtok_r`, splitting on spaces, and stores the count in `argc`.
  - It passes `argv[0]` as the file name to `load`, ensuring that the correct ELF binary is loaded.

The most important part here is to set up the user stack to match the layout above. I substantially modified `setup_stack` to do this.

The idea is:

1. Pass `argc` and `argv` into `setup_stack`.
2. Allocate and map a new user stack page at the top of user virtual memory.
3. Copy argument strings `argv[i]` onto the stack (from last to first).
4. Align the stack so that the final `esp` is properly **16‑byte aligned**.
5. Push the null sentinel, the `argv[i]` pointers, `argv`, `argc`, and a fake `return` address.
6. Store the final user stack pointer in `*esp`.

The core part of `setup_stack` looks like this:

```c
    /* We will build the stack in the newly mapped page.  User addresses
       in this page range are [PHYS_BASE - PGSIZE, PHYS_BASE).  To write
       into the user page we use the kernel mapping kpage with an offset
       of (user_addr - (PHYS_BASE - PGSIZE)). */
    uint8_t* user_page_bottom = (uint8_t*)(PHYS_BASE - PGSIZE);
    uint8_t* user_sp = (uint8_t*)PHYS_BASE;
    char* arg_ptrs[32];

    /* Copy argument strings onto the stack (from last to first). */
    for (int i = argc - 1; i >= 0; i--) {
      size_t len = strlen(argv[i]) + 1; /* include NUL */
      user_sp -= len;
      /* Compute kernel-side address and copy */
      memcpy(kpage + (user_sp - user_page_bottom), argv[i], len);
      arg_ptrs[i] = (char*)user_sp;
    }

    /* Do word align. */
    /* Compute size of metadata we will push after argument strings. */
    size_t meta_size =
        sizeof(char*)              /* NULL sentinel for argv[argc] */
        + argc * sizeof(char*)       /* argv[i] pointers */
        + sizeof(char**)             /* argv */
        + sizeof(int)                /* argc */
        + sizeof(void*);             /* fake return address */

    /* Extra words consumed on entry to user code. */
    const size_t kStartOverhead = 2 * sizeof(void*) + sizeof(void*); /* 12B */

    /* Address ESP would have after pushing meta_size + overhead. */
    uintptr_t want = (uintptr_t)user_sp - meta_size - kStartOverhead;
    size_t pad = want & 0xF;

    /* Pad so final ESP is 16-byte aligned. */
    user_sp -= pad;
    memset(kpage + (user_sp - user_page_bottom), 0, pad);

    /* Push a null sentinel for argv[argc]. */
    user_sp -= sizeof(char*);
    memset(kpage + (user_sp - user_page_bottom), 0, sizeof(char*));

    /* Push addresses of the argument strings (argv pointers) in reverse
       order so that argv[0] is at the lowest address in the array. */
    for (int i = argc - 1; i >= 0; i--) {
      user_sp -= sizeof(char*);
      char* ptr_val = arg_ptrs[i];
      memcpy(kpage + (user_sp - user_page_bottom), &ptr_val, sizeof(char*));
    }

    /* Save argv (pointer to argv[0]). */
    char** argv_addr = (char**)user_sp;

    /* Push argv (char**). */
    user_sp -= sizeof(char**);
    char** tmp_argv_addr = argv_addr;
    memcpy(kpage + (user_sp - user_page_bottom), &tmp_argv_addr, sizeof(char**));

    /* Push argc. */
    user_sp -= sizeof(int);
    int tmp_argc = argc;
    memcpy(kpage + (user_sp - user_page_bottom), &tmp_argc, sizeof(int));

    /* Push fake return address. */
    user_sp -= sizeof(void*);
    memset(kpage + (user_sp - user_page_bottom), 0, sizeof(void*));

    /* Finalize stack pointer for the user process. */
    *esp = (void*)user_sp;
  }
```

With this logic, the new user process starts with:

- a correctly aligned stack pointer,
- properly initialized `argc` and `argv` as seen by `_start` and `main`,
- and argument strings laid out exactly as expected by the calling convention.

## Process Control Syscalls

In this part, what we need to do is implement the process syscalls such as `exec`, `exit`, `wait` and `fork`. The challenge here is the **safety check** in each syscall and **message passing** between different functions. Also, to deal with the parent-child relationship mapping, it's important to build a structure `child` in `process.h`. Many of the functions require the use of this `child` structure. As following, I will explain the ideas and methods I used to construct this hard part. In this part, most work is completed in `syscall.c` and `process.c`. Also, I add some modifications in `thread.h` and `process.h`.

### What happens when there comes to a system call?

To make a system call, user program invokes `int $0x30`, pushing the syscall number and additional arguments into the stack before invoking the interrupt. Then, `syscall_handler` gets control. The system call number is in the 32-bit word at the caller’s stack pointer, the first argument is in the 32-bit word at the next higher address, and so on. The caller’s stack pointer is accessible to `syscall_handler` as the `esp` member of the `struct intr_frame` passed to it. `struct intr_frame` is on the kernel stack.

For example, when user program invokes the `exec("child-simple")` command:

1. `int $0x30` to invoke the interrupt, turn into the kernel function `syscall_handler`
2. Through the interrupt frame `f`, the kernel can get the `esp` pointer of the user stack, from which we can get syscall args.
3. In the stack, the args are stored in 4-byte frames (Pintos is running in a 32-bit environment) one by one. The arg pointed by `esp` (**arg[0]**) is the syscall number, in this example which is `2`. Following it, the arg pointed by `esp+4` (**arg[1]**) is `"child-simple"`, which is the name of the process being executed soon.

When the syscall finishes, some may returns a value. In that case, we need to save the value in `f->eax`. In the above example, `eax` needs to be set as the `pid` of the new process executed. After all these are completed, the kernel turns back to the user and continue the user program.

### Accessing user memory safely

As part of a system call, the kernel must often access memory through pointers provided by a user program. The kernel must be very careful about doing so, because the user can pass a null pointer, a pointer to unmapped virtual memory, or a pointer to kernel virtual address space (above `PHYS_BASE`). All of these types of invalid pointers must be rejected without harm to the kernel or other running processes, by terminating the offending process and freeing its resources.

To safely use user pointers, we add a check in our `syscall_handler`, implemented as the function `check_user_vaddr`. There are situations where some bytes of a system call argument lie in valid memory while other bytes lie in invalid memory, which we must handle very carefully. Therefore, we need a helper to read user virtual addresses byte by byte, checking whether each byte is valid:

```c
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault occurred. */
static int get_user(const uint8_t *uaddr) {
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
  : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool put_user(uint8_t *udst, uint8_t byte) {
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
  : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}
```

With these two functions, we can implement our check function (things about `Exit(-1)` will be explained when implementing the `exit` syscall, here it's only a way to kill the process because of an invalid syscall):

```c
/* Checks if a user virtual address is valid. If not, terminates the
   process. If WRITE is true, checks if the user address is writable. */
void check_user_vaddr(const void* vaddr, bool write) {
  if (!is_user_vaddr(vaddr)) Exit(-1);
  if (write) {
    if (!put_user((uint8_t*)vaddr, 0)) Exit(-1);
  } else {
    if (get_user((const uint8_t*)vaddr) == -1) Exit(-1);
  }
}
```

Although we have these checks, we still need a fallback mechanism in case a bad user pointer slips through and actually causes a hardware page fault. That “last line of defense” is implemented in the page‑fault handler `page_fault()` in `exception.c`.

When a page fault happens, the CPU fills in an error code. We decode it and in particular look at the `user` bit to decide whether the fault happened in user mode or in kernel mode:

- If the fault happened in **user mode** (user == true), we treat it as a bug in the offending user process. We simply call `Exit(-1)`. This covers cases where the user program itself dereferences an invalid pointer outside a system call.

- If the fault happened in **kernel mode** (user == false), it usually means some kernel code accidentally touched a bad user pointer without checking it first. In this case we do not want to crash the whole kernel. Instead, we adjust the saved interrupt frame so that execution “returns” from the system call with an error value.

  ```c
    if (user) {
      Exit(-1);
    } else {
      f->eip = (void *) f->eax;
      f->eax = 0xffffffff;
      return;
    }
  ```

This way, even if a buggy system call implementation dereferences an invalid user pointer and triggers a page fault in kernel mode, the kernel will survive and the user process will just see the system call fail with `-1`. Combined with `check_user_vaddr()`, `get_user()`, and `put_user()`, this provides both proactive checking and a robust fallback safety net against invalid user pointers.

### Building `syscall_handler`

Preparations are complete, and now we can start building `syscall_handler`, which is the main dispatcher for system calls. From the previous analysis, we already know what happens when a system call is invoked and why we must be careful with user pointers.

There are a few key pieces of data involved:

- `struct intr_frame *f`:  
  Captures the CPU state at the moment of the interrupt.  
  - `f->esp` points to the user stack at the time of the system call.  
  - `f->eax` is used to return the system call result back to the user program.

- `uint32_t args[4]`:  
  System call arguments are pushed on the user stack in 4‑byte slots.  
  - `args[0]` holds the system call number (defined in `syscall-nr.h`).  
  - `args[1]` and later entries hold the actual arguments passed by the user program.

So, **“how to get the arguments correctly and safely”** is the problem we must solve.

#### Safely reading the system call number and arguments

We cannot simply cast `f->esp` to a pointer and dereference it, because the user can place the stack pointer at:

- unmapped memory,
- kernel virtual addresses (above `PHYS_BASE`),
- or across a page boundary where only some bytes are valid.

If the kernel blindly dereferences such pointers, it may trigger a page fault in kernel mode and potentially crash the kernel.

To avoid this, we introduce helper functions that read user memory **byte by byte**, catching invalid addresses early:

```c
/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault occurred. */
static int get_user(const uint8_t *uaddr) {
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool put_user(uint8_t *udst, uint8_t byte) {
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}
```

On top of these, we add a generic address-checking helper:

```c
/* Checks if a user virtual address is valid. If not, terminates the
   process. If WRITE is true, checks if the user address is writable. */
void check_user_vaddr(const void* vaddr, bool write) {
  if (!is_user_vaddr(vaddr)) Exit(-1);
  if (write) {
    if (!put_user((uint8_t*)vaddr, 0)) Exit(-1);
  } else {
    if (get_user((const uint8_t*)vaddr) == -1) Exit(-1);
  }
}
```

With these helpers, we can implement `get_syscall_number` and `get_args` so that they verify every byte before using it:

```c
/* Get the syscall number from the user stack. */
uint32_t get_syscall_number(struct intr_frame* f) {
  uint8_t* uaddr = (uint8_t*)f->esp;
  uint32_t value = 0;

  for (int i = 0; i < 4; i++) {
    uint8_t* byte_addr = uaddr + i;
    if (!is_user_vaddr(byte_addr)) {
      Exit(-1);
    }
    int byte = get_user(byte_addr);
    if (byte == -1) {
      Exit(-1);
    }
    value |= ((uint32_t)byte & 0xFF) << (8 * i);
  }
  return value;
}

/* Get syscall arguments from the user stack. */
void get_args(struct intr_frame* f, uint32_t* args, int num) {
  for (int i = 1; i <= num; i++) {
    uint8_t* uaddr = (uint8_t*)f->esp + i * 4;
    uint32_t value = 0;

    /* Safely read 4 bytes for this argument from the user stack. */
    for (int j = 0; j < 4; j++) {
      uint8_t* byte_addr = uaddr + j;
      if (!is_user_vaddr(byte_addr)) {
        Exit(-1);
      }
      int byte = get_user(byte_addr);
      if (byte == -1) {
        Exit(-1);
      }
      value |= ((uint32_t)byte & 0xFF) << (8 * j);
    }
    args[i] = value;
  }
}
```

These two functions ensure:

- Every byte of the syscall number and each argument lies in valid user memory.
- If any byte is invalid, we immediately call `Exit(-1)` and terminate the offending process.
- The `num` parameter to `get_args` controls how many arguments we read, so we never walk past the valid part of the user stack.

#### Putting it together in `syscall_handler`

Now we can safely build the body of `syscall_handler`:

1. First, we sanity-check `f->esp` with `check_user_vaddr`.
2. Then we use `get_syscall_number(f)` to read the system call number.
3. For each specific system call, we call `get_args` with the appropriate num and then dispatch to the right handler.

This design avoids converting user pointers to kernel pointers for argument fetch. Instead, we validate and read arguments directly from the user stack, byte by byte, which is robust against **boundary tests** such as:

- arguments that straddle page boundaries
- arguments whose first byte is valid but remaining bytes are in unmapped or kernel space

The function body is just like this below:

```c
static void syscall_handler(struct intr_frame* f UNUSED) {
  check_user_vaddr(f->esp, false);
  uint32_t args[4];
  args[0] = get_syscall_number(f);
  if (args[0] == SYS_EXIT) {...}
  else if (args[0] == SYS_PRACTICE) {...}
  ...
  else { Exit(-1); }   // Syscall number is not valid.
}
```

### Tracking Child Processes: `struct child`

Before we can implement more complicated system calls such as `wait`, we need a way to track child processes. This is the purpose of the `struct child` abstraction.

#### Motivation

The `wait` system call must search among the caller’s children and find the one whose PID matches the argument. That immediately raises a question: **how do we keep track of all child processes of a given process, and how do we store each child’s state?**

From reading and debugging `process.c`, we know that:

- A new user process is created by calling `process_execute`, which in turn creates a **thread**.
- In the userprog design, each thread in a user process has a pointer to a PCB (`struct process *pcb`) that represents the process’s address space and shared process-wide state.

Since `struct thread` already exists as the basic unit of execution, it is the natural place to hang per-thread metadata. However, the “child process status” we want to track (PID, exit status, etc.) is conceptually a property of a **process as a child of its parent**, not of the PCB itself. Therefore, we introduce a separate `struct child` in `process.h` and connect it to threads via pointers and lists.

Concretely:

- We add a `struct list child_list` to `struct thread`, which stores all `struct child` records for that thread’s children.
- We also add `struct child *child_process` to `struct thread`, which points to the `struct child` describing this thread **as a child** of its parent (all processes except `init` can be a child).

This gives each parent thread a list of its children, and gives each child thread a direct pointer to its own status record.

#### The `child` structure

We define `struct child` as follows:

```c
struct child {
   pid_t pid;
   int exit_status;
   bool exited;
   bool waiting;
   bool killed;
   bool loaded;
   struct semaphore wait_sema;
   struct semaphore load_sema;
   struct list_elem elem;
};
```

The fields serve these roles:

- `pid`: the PID (same as the TID of the child’s main thread).
- `exit_status`: the exit status reported by the child.
- `exited`: set to `true` once the child has finished execution.
- `waiting`: set to `true` once the parent has called `wait` on this child, so we can prevent multiple waits on the same PID.
- `killed`: set when the child is terminated by the kernel due to an exception or invalid system call; in that case the parent sees `-1`.
- `loaded`: indicates whether the child successfully loaded its executable (used to implement `exec` and propagate load failure back to the parent).

We also use two semaphores to synchronize between parent and child:

- `wait_sema`: used by `process_wait` to block the parent until the child has exited.
- `load_sema`: used by `process_execute` to block the parent until the child has finished loading its executable and set loaded.

Finally, `elem` is the list element used to link this struct child into the parent’s `child_list`.

#### Initializing the structure

In function `init_thread` in `thread.c`, we need to add these:

```c
  list_init(&t->child_list);
  t->child_process = NULL;
```

In `process.c`, I create a initializer for each `child`:

```c
/* Initializes a child process structure and adds it
   to the current thread's list of children. */
struct child* child_init() {
  struct child* child_proc = malloc(sizeof(struct child));
  child_proc->pid = TID_ERROR;
  child_proc->exit_status = -1;
  child_proc->waiting = false;
  child_proc->killed = false;
  child_proc->exited = false;
  child_proc->loaded = false;
  sema_init(&child_proc->wait_sema, 0);
  sema_init(&child_proc->load_sema, 0);
  list_push_back(&thread_current()->child_list, &child_proc->elem);
  return child_proc;
}
```

In the initializer, we set the initial `pid` of every child as `TID_ERROR`. When the child process being executed successfully, it will be changed into the real `pid` of the new process.

Every time we execute a new program or fork a process, we need this initializer to initialize the `child` structure of the new process.

#### Usage across system calls

Once this structure is in place, all relevant system calls (`exec`, `wait`, page-fault handling that kills a process, etc.) maintain and consult struct child:

- `process_execute` creates a new struct child, inserts it into the current thread’s `child_list`, and uses `load_sema` to wait for the child’s load result.
- `start_process` (running in the child) updates `loaded`, `exit_status`, and signals `load_sema` and `wait_sema` as appropriate.
- `process_wait` looks up the correct struct child by PID, waits on `wait_sema` if necessary, and returns the stored `exit_status`.

This design cleanly separates *per-process address space state* (`struct process`) from *per-child relationship state* (`struct child`), and gives us a robust foundation for implementing `wait` and other process control system calls. When we build the system calls in detail, we will talk about how and when to use/set the status and semaphores.

**Notice: The `child_process` in `thread` is not any real child process of current process! It's just a pointer that points to a `child` structure which stores some property of the current process as a child process.** It's kind of weird, I don't remember how I came up with the idea of doing this, but that's it.

### Details of system calls

In this section, I will describe how each system call is implemented in Pintos kernel.

#### `SYS_PRACTICE`

This is its signature in user program:

```c
int practice (int i); 
```

It's a simple system call. What it does is just returning `i + 1`. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_PRACTICE) {
    get_args(f, args, 1);
    f->eax = args[1] + 1;
}
```

------

#### `SYS_HALT`

This is its signature in user program:

```c
void halt(void);
```

It's also a simple system call. When it's invoked, the Pintos kernel will be terminated by `shutdown_power_off()` function. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_HALT) {
    shutdown_power_off();
}
```

------

#### `SYS_EXIT`

This is its signature in user program:

```c
void exit (int status); 
```

`exit` terminates the current user program and records an exit status that can later be observed by the kernel and by the parent process (via `wait`). It is therefore tightly connected to the implementation of `wait`, which I will discuss later. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_EXIT) {
    get_args(f, args, 1);
    f->eax = args[1];
    Exit(args[1]);
}
```

In `process.c`, Pintos provides a skeleton `process_exit` function. It already performs the core work of destroying the address space and freeing the PCB, but it leaves some details to us. On top of that, I introduce an `Exit()` helper in `syscall.c`, which is the kernel entry point used by the `SYS_EXIT` system call:

```c
void Exit(int status) {
  struct child* cp = thread_current()->child_process;
  if (cp != NULL) {
    cp->exit_status = status;
  }
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  process_exit();
}
```

`Exit()` does three things:

1. Looks up the `struct child*` that represents this process as a child of its parent (`thread_current()->child_process`).
2. If it exists, stores the final `exit_status` into that child structure so that `wait(pid)` can later return it.
3. Prints the standard Pintos exit message and then calls `process_exit()` to clean up the process and terminate the thread.

By convention, an exit status of `0` means normal termination, and a non‑zero status (for example `Exit(-1)`) indicates abnormal termination or that the process was killed. Whenever we detect a serious error (e.g., invalid user pointer, bad system call arguments), we simply call `Exit(-1)` to stop the process immediately.

On top of the original `process_exit` skeleton in `process.c`, I add extra logic to maintain the child structures:

```c
  /* Free the current process's child processes. */
  if (!list_empty(&cur->child_list)) {
    for (e = list_begin(&cur->child_list); e != list_end(&cur->child_list);) {
      cp = list_entry(e, struct child, elem);
      struct list_elem* next = list_next(e);
      list_remove(&cp->elem);
      free(cp);
      e = next;
    }
  }
  
  if (cur->child_process) {
    cur->child_process->exited = true;
    sema_up(&cur->child_process->wait_sema);
  }
```

When a process exits, all of its pages are destroyed and its PCB is freed, so its children effectively lose their parent. Before tearing everything down, I iterate over `cur->child_list` and remove/free every `struct child` entry, ensuring that no stale parent–child relationships remain.

Then, if the current process itself has a `child_process` record (i.e., it is a child of some parent), I set `exited = true` and signal `wait_sema`. This wakes up any parent that is blocked in `process_wait(pid)` so that it can read the recorded `exit_status`. The details of how the parent consumes this information will be described in the section on `wait`.

------

#### `SYS_EXEC`

This is its signature in user program:

```c
pid_t exec (const char *cmd_line); 
```

`exec` runs the executable whose name is given in `cmd_line`, passing any given arguments, and returns the new process’s program id (`pid`). If the program cannot load or run *for any reason*, return `-1`. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_EXEC) {
    get_args(f, args, 1);
    check_user_string((const char*)args[1]);
    f->eax = process_execute((const char*)args[1]);
}
```

The core logic lives in `process_execute` and `start_process` in `process.c`.

Before them, `check_user_string(const char *str)` is a function that ensures the entire NUL‑terminated string lies in valid user memory:

- It first checks the starting address with `check_user_vaddr(str, false)`.
- Then it walks forward byte by byte, calling `get_user` on each byte until it finds the terminating `'\0'`.
- If any byte access returns `-1` or crosses into an invalid user address, it immediately calls `Exit(-1)` and kills the process.

This is especially important for `exec`, because the command line can straddle page boundaries or partially point into unmapped memory. By validating the full string up front, we guarantee that `process_execute` and `load` never dereference an invalid `cmd_line` pointer inside the kernel.

```c
/* Checks if a user string is valid. If not, terminates the process. */
void check_user_string(const char* str) {
  const uint8_t* ptr = (const uint8_t*)str;
  check_user_vaddr((void*)ptr, false);
  while (ptr++) {
    int get = get_user(ptr);
    if (get == -1) Exit(-1);  // invalid
    if (get == 0) break;  // '/0'
  }
}
```

I found this problem and many other ones like this when I'm checking the tests. It reminds me that it's important to test all the malicious cases you can think of. Some insignificant details may ruin the entire project.

`process_execute` is responsible for creating a new process and returning its PID to the caller of `exec`. Conceptually, it does:

1. Take the full command line `file_name` and make a copy `fn_copy` using `palloc_get_page`, so that there is no race between load (which runs in the child thread) and the original buffer.
2. Extract the actual `program_name` (the part before the first `space`) from the command line, and use it as the thread name for the new process.
3. Allocate and initialize a new `struct child *child_proc` via `child_init()`. This structure will represent the new process as a child of the current one and will be used later by wait.
4. Create an `exec_helper` structure that bundles together `fn_copy` and `child_proc`, and pass it as the `aux` argument to `start_process` via `thread_create`. We need this helper because `start_process` only receives a single pointer but still needs both the command line copy and the child record created by the parent (because we need the `load_sema` of every child process to synchronize, which can't be a global variable and must be in the `child` structure). It really confused me for a long time.
5. After `thread_create` returns, the parent immediately calls `sema_down(&child_proc->load_sema)` to wait until the child finishes loading the executable. Only then does `process_execute` know whether loading succeeded.
6. When the child thread runs `start_process`, it will:
   - Unpack the `exec_helper` and recover both `file_name` and `child_proc`.
   - Set `thread_current()->child_process = child_proc` so that later `Exit()` / `process_exit()` can update this record.
   - Split the command line into `argc` / `argv` and call `load(argv[0], &eip, &esp, argc, argv)`.
   - If load fails, it sets the appropriate flags/status in `child_proc` (e.g., `exit_status = -1`, `exited = true`), signals `load_sema`, and then exits the thread.
   - If load succeeds, it sets `child_proc->loaded = true`, signals `load_sema`, and jumps to user mode.
7. When the parent is woken up from `sema_down(&child_proc->load_sema)`, it inspects `child_proc->loaded`:
   - If `loaded == false`, it treats this as an `exec` failure, cleans up `child_proc`, and returns `TID_ERROR` (seen as `-1` in user space).
   - If `loaded == true`, it stores the child’s `tid` as `child_proc->pid` and returns that PID to the caller.

The structure of `process_execute` in code looks like:

```c
/* Helper structure for exec to send something to child process.*/
struct exec_helper {
  char* file_name;
  struct child* child_proc;
};

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL) return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);
  /* Save the program name. */
  char program_name[32];
  int i = 0;
  while (file_name[i] != ' ' && file_name[i] != '\0' && i < (int)sizeof(program_name) - 1) {
    program_name[i] = file_name[i];
    i++;
  }
  program_name[i] = '\0';

  /* Create and initialize a child process structure. */
  struct child* child_proc = child_init();
  if (child_proc == NULL) {
    palloc_free_page(fn_copy);
    free(child_proc);
    return TID_ERROR;
  }

  struct exec_helper* helper = malloc(sizeof(struct exec_helper));
  helper->file_name = fn_copy;
  helper->child_proc = child_proc;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(program_name, PRI_DEFAULT, start_process, helper);
  sema_down(&child_proc->load_sema); // Wait for child to load
  if (!child_proc->loaded) tid = TID_ERROR;
  if (tid == TID_ERROR) {
    list_remove(&child_proc->elem);
    free(child_proc);
  } else {
    child_proc->pid = tid;
  }
  return tid;
}
```

By using `load_sema` for synchronization, `exec` behaves as a synchronous system call with respect to program loading: the parent only returns from `exec` after the child has either successfully loaded the executable or definitively failed, returning a correct `pid` or `-1` to user space.

------

#### `SYS_WAIT`

This is its signature in user program:

```c
int wait (pid_t pid); 
```

`wait` is the function with the largest workload. It waits for a child process `pid` and retrieves the child’s exit status. Because it must locate the correct child by PID and track its lifetime, this call is the main motivation for introducing the `struct child`  abstraction described earlier. That structure did cause quite a bit of trouble, but it is the key to making `wait` work correctly. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_WAIT) {
    get_args(f, args, 1);
    f->eax = process_wait((pid_t)args[1]);
}
```

The core logic lives in `process_wait` in `process.c`.

The first thing wait needs to do is to find the correct child process with the given `pid`. This is where the `child_list` we attached to `struct thread` comes in. wait is always called in the **parent** process, so we just traverse the current thread’s `child_list` and compare each child’s `pid` with the given one. If we find a match, we have found the child we care about; if not, `pid` is not a valid child.

I implement this in a helper function:

```c
struct child* find_child(pid_t pid) {
  struct thread* t = thread_current();
  struct list_elem* e;
  for (e = list_begin(&t->child_list); e != list_end(&t->child_list); e = list_next(e)) {
    struct child* c = list_entry(e, struct child, elem);
    if (c->pid == pid) 
      return c;
  }
  return NULL;
}
```

Now we can use `find_child` at the beginning of `process_wait` to locate the child struct. 

There are several cases where `wait` must immediately return `-1` without blocking:

- `pid` is not a direct child of the caller (`find_child` returns `NULL`).
- wait has already been successfully called on `pid` (traced by the `waiting` flag)
- the child was terminated by the kernel (traced by the `killed` flag set in function `kill` in `exception.c`)

Putting this together, `process_wait` looks like this:

```c
/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an exception), returns -1.
   If child_pid is invalid or if it was not a child of the calling process,
   or if process_wait() has already been successfully called for the given PID,
   returns -1 immediately, without waiting. */
int process_wait(pid_t child_pid UNUSED) {
  struct child* child = find_child(child_pid);
  if (child == NULL || child->waiting) {
    return -1;
  }
  child->waiting = true;
  if (!child->exited) {
    sema_down(&child->wait_sema); // Wait for child to exit
  }
  if (child->killed) {
    child->exit_status = -1;
    list_remove(&child->elem);
    free(child);
    return -1;
  }
  int status = child->exit_status;
  list_remove(&child->elem);
  free(child);
  return status;
}
```

A nice property of this design is that if the child **already exited before** the parent calls `wait`, then `child->exited` is already `true` and `sema_down` is skipped. In that case wait simply returns immediately with the cached `exit_status`.

To make the `killed` flag meaningful, we also need to update it when the kernel aborts a process due to an exception (for example, a page fault caused by an invalid user pointer). That happens in `kill` in `exception.c`. There I add:

```c
struct thread* t = thread_current();
if (t->child_process != NULL) {
    t->child_process->exited = true;
    t->child_process->killed = true;
}
```

This marks the current process’s child record as both `exited` and `killed`. Later, when the parent calls `wait(pid)`, `process_wait` will see `child->killed == true` and return `-1` instead of a normal exit status.

Combined with the `Exit() / process_exit()` path (which sets `exited = true`, fills in `exit_status`, and signals `wait_sema`), this gives us a complete picture:

- Normal calls to `exit(status)` store `exit_status` and wake any waiting parent.
- Kernel errors or exceptions mark the child as `killed` and still wake the parent.
- `wait` uses `find_child`, `waiting`, `exited`, `killed`, and `wait_sema` to implement exactly the Pintos `wait` semantics without busy-waiting.

------

#### `SYS_FORK`

This is its signature in user program:

```c
pid_t fork (void); 
```

The `fork` system call creates a copy of the calling process, including its address space (and later its file descriptors). We call the original process the **parent** and the new one the **child**. The expected behavior is:

- In the **parent process**, `fork` returns the child’s program id (`pid`). The PID must be unique. If the child cannot be created or run, `fork` should return `-1`.
- In the **child process**, `fork` returns `0`.
- The child is considered a direct child of the caller for the purposes of `wait`.
- The child eventually has a copy of the parent’s file descriptors, pointing to the same underlying `struct file` objects (I will handle the descriptor table separately). We can ignore stdin/stdout for now.

As the project handout suggests, I implemented `exec` and `wait` first, and then built `fork` on top of the same ideas. In particular, the design of `fork` is heavily inspired by `process_execute`, `start_process`, and `load`.

In `syscall_handler`, the `SYS_FORK` case is very simple:

```c
if (args[0] == SYS_FORK) {
  f->eax = fork(f);
}
```

The real work happens in `fork` and `fork_process` in `syscall.c`.

The key idea is:

- In the **parent**, fork allocates a `struct child`, snapshots the parent’s CPU state (`struct intr_frame`), and creates a new kernel thread that will run `fork_process` in the child context.
- In the child, `fork_process`:
  - builds a new PCB,
  - allocates a fresh page directory,
  - copies the parent’s address space with `pagedir_copy`,
  - adjusts the copied `intr_frame` so that `eax = 0`,
  - and then jumps into user mode with this frame, making it look like `fork` just returned `0` in the child.

Synchronization between parent and child is done through the `child` structure and the `load_sema` semaphore, very similar to how `exec` uses `load_sema` to report success or failure back to the parent.

With these ideas, we can start building `fork` now. Just like `exec` uses an `exec_helper` to pass the `child` into `start_process`, fork also uses a helper structure:

```c
struct fork_helper {
  struct thread* parent;
  struct child* child_proc;
  struct intr_frame if_;
};
```

This bundles three things:

- `parent`: a pointer to the parent thread,
- `child_proc`: the struct child record created in the parent,
- `if_`: a copy of the parent’s interrupt frame at the time of the system call.

We pass a pointer to this `fork_helper` as the `aux` argument to `thread_create`, so that `fork_process` running in the child can see all of this state.

The overall idea of `fork` is very similar to `process_execute`, but with some important differences. In `fork`, we want to copy **all** of the parent’s state, not start a new program.

In the `fork` function, we first get the parent thread `cur = thread_current()`, then create a new `struct child *child_proc` to represent the future child. I pack `cur`, `child_proc`, and a copy of the parent’s interrupt frame into a `fork_helper` structure. The interrupt frame is copied with `memcpy`, because it’s a value, not a pointer. Then we call `thread_create` with `fork_process` and the helper, and wait on `child_proc->load_sema` until the child finishes its setup. If creation fails at any point, `fork` returns `-1`. Otherwise, it stores the child’s `tid` into `child_proc->pid` and returns this PID to the parent. Here is the function:

```c
pid_t fork(struct intr_frame* f) {
  struct thread* cur = thread_current();
  struct child* child_proc = child_init();
  if (child_proc == NULL)  return -1;
  struct fork_helper* helper = malloc(sizeof(struct fork_helper));
  helper->parent = cur;
  helper->child_proc = child_proc;
  memcpy(&helper->if_, f, sizeof *f);
  tid_t tid = thread_create(cur->name, cur->priority, fork_process, helper);
  sema_down(&child_proc->load_sema);
  if (tid == TID_ERROR) {
    list_remove(&child_proc->elem);
    free(child_proc);
    free(helper);
    return -1;
  } else {
    child_proc->pid = tid;
  }
  return tid;
}
```

`fork_process` runs in the new child thread and is strongly inspired by `start_process` and `load`. It unpacks the helper to get `child_proc`, the parent pointer, and the copied `intr_frame` `if_`. It initializes a new PCB for the child, then needs to duplicate the parent’s address space. To do that, we first create a fresh page directory for the child with `pagedir_create`, and then call `pagedir_copy(child->pcb->pagedir, parent->pcb->pagedir)` to clone all user pages. After the copy succeeds, we call `process_activate()` so the child uses its own page table, set `if_->eax = 0` so that the child sees `fork()` return `0`, signal `child_proc->load_sema` to wake the parent, and finally jump back to user mode using the copied interrupt frame.

```c
static void fork_process(void* addr) {
  struct fork_helper* helper = (struct fork_helper*)addr;
  struct thread* parent = helper->parent;
  struct child* child_proc = helper->child_proc;
  struct thread* child = thread_current();
  struct intr_frame* if_ = &helper->if_;
  child->child_process = child_proc;
  bool success, pcb_success, cp_success;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    new_pcb->pagedir = NULL;
    child->pcb = new_pcb;
    child->pcb->main_thread = child;
    strlcpy(child->pcb->process_name, child->name, sizeof child->name);
  }
  
  /* Copy parent's address space */
  if (success) {
      /* Allocate and activate page directory. */
    child->pcb->pagedir = pagedir_create();
    if (child->pcb->pagedir == NULL)
      goto done;
    cp_success = pagedir_copy(child->pcb->pagedir, parent->pcb->pagedir);
    if (!cp_success) goto done;
    process_activate();
  }
  /* Set up the child's intr_frame */
  if (success) {
    if_->eax = 0; // Child's fork() return value is 0
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = child->pcb;
    child->pcb = NULL;
    free(pcb_to_free);
  }

done:
  if (!success) {
    sema_up(&child_proc->load_sema);
    thread_exit();
  }
  sema_up(&child_proc->load_sema);
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(if_) : "memory");
  NOT_REACHED();
}
```

`pagedir_copy` in `pagedir.c` does the actual page table cloning. It iterates over all user PDEs in the source page directory. For each present page table entry, it computes the user virtual address, gets the corresponding kernel page with `pagedir_get_page(src, upage)`, allocates a new user page with `palloc_get_page(PAL_USER)`, copies the contents with `memcpy`, and then installs the new page into the destination page directory using `pagedir_set_page`, preserving the original writable bit. If any allocation or mapping fails, it returns `false`. If it successfully walks all entries, it returns `true`, and the child ends up with a full copy of the parent’s user address space.

```c
bool pagedir_copy(uint32_t *dst, uint32_t *src) {
  for (uint32_t pd_idx = 0; pd_idx < pd_no(PHYS_BASE); pd_idx++) {
    uint32_t *pde = src + pd_idx;
    if (*pde & PTE_P) {
      uint32_t *pt = pde_get_pt(*pde);
      for (int pt_idx = 0; pt_idx < 1024; pt_idx++) {
        uint32_t pte = pt[pt_idx];
        if (pte & PTE_P) {
          void *upage = ((pd_idx << 22) | (pt_idx << 12));
          void *kpage = pagedir_get_page(src, upage);
          if (kpage == NULL) continue;

          void *new_page = palloc_get_page(PAL_USER);
          if (new_page == NULL) return false;
          memcpy(new_page, kpage, PGSIZE);

          bool writable = (pte & PTE_W) != 0;
          if (!pagedir_set_page(dst, upage, new_page, writable)) {
            palloc_free_page(new_page);
            return false;
          }
        }
      }
    }
  }
  return true;
}
```

Now, we've finished all the process control system calls. What a great thing I've done! It's really a hard thing to understand what I need to do, and how Pintos really works. Until finish this part, it has already taken me two months to do it. Hope I can do better in the next parts.

## File Operation Syscalls

In this part, we focus on some file operation syscalls, including `create`, `remove`, `open`, `filesize`, `read`, `write`, `seek`, `tell` and `close`.

### Synchronization

Pintos’ file system is not thread-safe, so we must make sure that our file operation syscalls do not call multiple file system functions concurrently. Thus in this project, we use a simple **global lock** `filesys_lock` on all file system operations and syscalls.

While a user process is running, nobody can modify its executable on disk, which means we should add some protective measures on our origin `load`. Therefore, we declare `filesys_lock` as `extern` in `syscall.h` so that both `syscall.c` and `process.c` can use the same lock instance consistently.

For each file-related syscall, the kernel **acquires** `filesys_lock` before calling into the file system layer and **releases** it before returning to user mode. For `load`, we also need additional logic (discussed later) to deny writes to the currently running executable.

### Details of syscalls

In this section, I describe how each file operation system call is implemented in Pintos kernel. For clarity, I implement a small kernel helper function for each syscall.

#### `CREATE`

This is its signature in user program:

```c
bool create (const char *file, unsigned initial_size);
```

The syscall creates a new file called `file` initially `initial_size` bytes in size. It returns true if successful, false otherwise. Because `file` is a user pointer to a string, we must validate it using `check_user_string`, similar to what we do in `exec`. There are 2 args, the first one is the `file` name, the second one is the file's `initial_sieze`. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_CREATE) {
    get_args(f, args, 2);
    check_user_string((const char*) args[1]);
    f->eax = create((const char*) args[1], (unsigned) args[2]);
}
```

In `filesys.c`, we already have a raw function `filesys_create` for creating a file. So we only need to invoke this function in our syscall function, and judge whether the `create` operation is successful.

```c
bool create(const char* file, unsigned initial_size) {
    lock_acquire(&filesys_lock);
    bool result;
    result = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return result;
}
```

------

#### `REMOVE`

This is its signature in user program:

```c
bool remove (const char *file);
```

The syscall deletes the file named `file`. It returns true if successful, false otherwise. A file may be removed regardless of whether it is open or closed, and removing an open file does not close it. As before, `file` is a user string pointer, so we validate it with `check_user_string` before performing the operation. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_REMOVE) {
    get_args(f, args, 1);
    check_user_string((const char*) args[1]);
    f->eax = remove((const char*) args[1]);
}
```

Also, we already have `filesys_remove`, so we just invoke it.

```c
bool remove(const char* file) {
    lock_acquire(&filesys_lock);
    bool result;
    result = filesys_remove(file);
    lock_release(&filesys_lock);
    return result;
}
```

------

#### `OPEN`

This is its signature in user program:

```c
int open (const char *file);
```

The syscall opens the file named `file`. It returns a nonnegative integer handle called a “file descriptor” (`fd`), or `-1` if the file could not be opened. When a single file is opened more than once, whether by a single process or different processes, each open returns a new file descriptor. Different file descriptors for a single file are closed independently in separate calls to `close` and they do **not** share a file position. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_OPEN) {
    get_args(f, args, 1);
    check_user_string((const char*)args[1]);
    f->eax = open((const char*)args[1]);
}
```

A file descriptor is a process-level abstraction: each process maintains its own independent set of file descriptors, and each descriptor represents one open file within that process. In Pintos, file descriptors `0` and `1` are reserved for the console: `0` (`STDIN_FILENO`) corresponds to standard input, and `1` (`STDOUT_FILENO`) corresponds to standard output. Therefore, our file descriptor allocation should start from `2`. Later, when implementing `read` and `write`, we also need to handle these two special `fd`s as dedicated cases.

To support per-process file descriptors, we extend `struct thread`. In this project, a process is essentially a thread with an associated `pcb`, so process-specific state is naturally stored in this core structure. We add:

```c
int next_fd; /* Next file descriptor to be assigned */
struct list open_files; /* List of open files */
```

Here, `next_fd` is initialized to `2` and increments by one each time the process opens a new file. Meanwhile, `open_files` is used to track the set of files currently opened by the process. But what exactly is stored in this list? We need a structure that binds together an `fd` number and its corresponding `file` object, which leads to the following helper structure in `process.h`:

```c
/* Tracks open files for a process. */
struct pfile {
   struct file* file;
   int fd; // file descriptor
   struct list_elem elem;
};
```

With this design, the `open_files` list stores `struct pfile` entries.

With the data structures in place, the syscall implementation is straightforward:

```c
int open(const char* file) {
    lock_acquire(&filesys_lock);
    int fd = -1;
    struct file* f = filesys_open(file);
    if (!f) {
        lock_release(&filesys_lock);
        return fd;
    }
    fd = process_open_file(f);
    lock_release(&filesys_lock);
    return fd;
}
```

We still use the existing `filesys_open`, which returns the `struct file*` for the target file. If the file does not exist (or cannot be opened), we return `-1` to indicate failure. Otherwise, we allocate a new `fd` for this open instance by calling `process_open_file`. Since file descriptors are maintained per process, this helper is placed in `process.c`. Its job is simply to create a `struct pfile` entry for the opened `file`, assign it a fresh `fd`, increase the `next_fd` of the process, and push it into the current process’s `open_files` list:

```c
/* Allocates a file descriptor to an open file.*/
int process_open_file(struct file* f) {
    struct thread* t = thread_current();
    struct pfile* pf = malloc(sizeof(struct pfile));
    if (pf == NULL) return -1;
    pf->file = f;
    pf->fd = t->next_fd++;
    list_push_back(&t->open_files, &pf->elem);
    return pf->fd;
}
```

------

#### `FILESIZE`

This is its signature in user program:

```c
int filesize (int fd);
```

The syscall returns the size, in bytes, of the open file with file descriptor `fd`. It returns `-1` if `fd` does not correspond to an entry in the file descriptor table. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_FILESIZE) {
    get_args(f, args, 1);
    f->eax = filesize(args[1]);
}
```

To implement this syscall, the key is to translate an `fd` into the underlying `struct file*`. This is exactly why we maintain the `(fd, file)` mapping using `struct pfile` entries stored in the per-process `open_files` list. With this design, we can simply traverse the list, locate the `pfile` whose `fd` matches the target, and return its associated file pointer. This is done by `process_get_file`:

```c
/* Retrieves the file associated with a given file descriptor.*/
struct file* process_get_file(int fd) {
    struct thread* t = thread_current();
    struct list_elem* e;
    for (e = list_begin(&t->open_files); e != list_end(&t->open_files); e = list_next(e)) {
        struct pfile* pf = list_entry(e, struct pfile, elem);
        if (pf->fd == fd) {
            return pf->file;
        }
    }
    return NULL;
}
```

Once we have the file pointer, `filesize` becomes a thin wrapper around Pintos’s `file_length`. If `process_get_file` returns `NULL`, we keep the default result `-1`:

```c
int filesize(int fd) {
    lock_acquire(&filesys_lock);
    int size = -1;
    struct file* f = process_get_file(fd);
    if (f != NULL) {
        size = file_length(f);
    }
    lock_release(&filesys_lock);
    return size;
}
```

------

#### `READ`

This is its signature in user program:

```c
int read (int fd, void *buffer, unsigned size);
```

The syscall reads `size` bytes from the file open as `fd` into `buffer`. Returns the number of bytes actually read (0 at end of file), or `-1` if the file could not be read (due to a condition other than end of file, such as `fd` not corresponding to an entry in the file descriptor table). 

At this point, we face a new safety issue: `buffer` is a user pointer, so the user may pass a null pointer, an unmapped pointer, or a pointer that crosses into invalid memory. To handle this, I reuse the idea of `check_user_vaddr` and validate the entire memory range `[buffer, buffer + size)` byte by byte. This leads to a simple helper:

```c
/* Checks if a user buffer for read and write is valid. */
void check_user_buffer(const void* buffer, unsigned size, bool write) {
    void* ptr = (void*)buffer;
    for (unsigned i = 0; i < size; i++) {
        check_user_vaddr(ptr + i, write);
    }
}
```

With this security guarantee, we can continue. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_READ) {
    get_args(f, args, 3);
    check_user_buffer((const void*)args[2], (unsigned)args[3], true);
    f->eax = read(args[1], (void*)args[2], (unsigned)args[3]);
}
```

As mentioned earlier, there are two special file descriptors: `STDIN_FILENO` (0) and `STDOUT_FILENO` (1). For `read`, when `fd == STDIN_FILENO`, we should read from the keyboard. Pintos provides `input_getc` function in `devices/input.c`, so in this case we fetch characters from the device driver and store them into the user buffer one by one.

For the normal case (`fd` refers to an actual file), we still use `process_get_file(fd)` to locate the corresponding `struct file*` in the current process, and then call Pintos’s `file_read`.

```c
int read(int fd, void* buffer, unsigned size) {
    if (fd == STDIN_FILENO) {
        uint8_t* buf = (uint8_t*)buffer;
        for (unsigned i = 0; i < size; i++) {
            buf[i] = input_getc();
        }
        return size;
    }
    lock_acquire(&filesys_lock);
    struct file* f = process_get_file(fd);
    if (f == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }
    int bytes_read = file_read(f, buffer, size);
    lock_release(&filesys_lock);
    return bytes_read;
}
```

------

#### `WRITE`

This is its signature in user program:

```c
int write (int fd, const void *buffer, unsigned size);
```

The syscall writes `size` bytes from `buffer` to the open file with file descriptor `fd`. It returns the number of bytes actually written, which may be less than `size` if some bytes could not be written. Returns `-1` if `fd` does not correspond to an entry in the file descriptor table. As `read`, we also need `check_user_buffer` for safety. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_WRITE) {
    get_args(f, args, 3);
    check_user_buffer((const void*)args[2], (unsigned)args[3], false);
    f->eax = write(args[1], (const void*)args[2], (unsigned)args[3]);
}
```

For `fd == STDOUT_FILENO`, Pintos requires that small outputs should be written in one `putbuf` call to reduce interleaving between processes. For large buffers, it is acceptable to split them into chunks. In our implementation, we write to the console in fixed-size chunks (`STDOUT_CHUNK`), then return `size` as the number of bytes written.

For normal files, we retrieve the underlying `struct file*` using `process_get_file(fd)` and call `file_write`.

```c
int write(int fd, const void* buffer, unsigned size) {
    if (fd == STDOUT_FILENO) {
        #define STDOUT_CHUNK 256
        const char* buf = (const char*)buffer;
        unsigned remaining = size;
        while (remaining > 0) {
            unsigned chunk = remaining > STDOUT_CHUNK ? STDOUT_CHUNK : remaining;
            putbuf(buf, chunk);
            buf += chunk;
            remaining -= chunk;
        }
        return size;
    }
    lock_acquire(&filesys_lock);
    struct file* f = process_get_file(fd);
    if (f == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }
    int bytes_written = file_write(f, buffer, size);
    lock_release(&filesys_lock);
    return bytes_written;
}
```

------

#### `SEEK`

This is its signature in user program:

```c
void seek (int fd, unsigned position);
```

The syscall changes the next byte to be read or written in open file `fd` to `position`, expressed in bytes from the beginning of the file. Thus, a position of 0 is the file’s start. If `fd` does not correspond to an entry in the file descriptor table, this function should do nothing. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_SEEK) {
    get_args(f, args, 2);
    seek(args[1], (unsigned)args[2]);
}
```

The kernel helper locks the file system, looks up the file, and calls `file_seek` if the descriptor is valid:

```c
void seek(int fd, unsigned position) {
    lock_acquire(&filesys_lock);
    struct file* f = process_get_file(fd);
    if (f != NULL) {
        file_seek(f, position);
    }
    lock_release(&filesys_lock);
}
```

------

#### `TELL`

This is its signature in user program:

```c
int tell(int fd);
```

The syscall returns the position of the next byte to be read or written in open file `fd`, expressed in bytes from the beginning of the file. If the operation is unsuccessful, it can either `exit` with `-1` or it can just fail silently. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_TELL) {
    get_args(f, args, 1);
    f->eax = tell(args[1]);
}
```

Implementation: protect with lock, fetch the file, and call `file_tell`:

```c
int tell(int fd) {
    lock_acquire(&filesys_lock);
    int position = -1;
    struct file* f = process_get_file(fd);
    if (f != NULL) {
        position = file_tell(f);
    }
    lock_release(&filesys_lock);
    return position;
}
```

------

#### `CLOSE`

This is its signature in user program:

```c
void close (int fd);
```

The syscall closes file descriptor `fd`. If the operation is unsuccessful, it can either `exit` with `-1` or it can just fail silently. In `syscall_handler`, it's implemented like below:

```c
if (args[0] == SYS_CLOSE) {
    get_args(f, args, 1);
    close(args[1]);
}
```

When a process tries to close a file, we first locate the open file corresponding to the given `fd`, call `file_close` on it, and then remove the associated entry from the `open_files` list.

```c
/* Closes the file associated with a given file descriptor.*/
void process_close_file(int fd) {
  struct thread* t = thread_current();
  struct list_elem* e;
  for (e = list_begin(&t->open_files); e != list_end(&t->open_files); e = list_next(e)) {
    struct pfile* pf = list_entry(e, struct pfile, elem);
    if (pf->fd == fd) {
      file_close(pf->file);
      list_remove(&pf->elem);
      free(pf);
      return;
    }
  }
}
```

This is implemented by `process_close_file`. Therefore, in the `close` syscall, once we confirm that the `fd` is valid and obtain the corresponding `struct file*`, we simply call `process_close_file(fd)` to perform the actual close and cleanup.

```c
void close(int fd) {
    lock_acquire(&filesys_lock);
    struct file* f = process_get_file(fd);
    if (f != NULL) {
        process_close_file(fd);
    }
    lock_release(&filesys_lock);
}
```

### Additional work for file operations

Until now, we have already finish all the system call functions we need in this project, but as the file system be introduced to every process, there is some other work we need to do.

#### Close all the files when process exits

When a process exits, it's essential to close all the files it opened. Thus, we need to add something to our `process_exit` function to close the files:

```c
/* Close all open files. */
if (!list_empty(&cur->open_files)) {
    lock_acquire(&filesys_lock);
    struct list_elem* e;
    for (e = list_begin(&cur->open_files); e != list_end(&cur->open_files);) {
        struct pfile* pf = list_entry(e, struct pfile, elem);
        struct list_elem* next = list_next(e);
        file_close(pf->file);
        list_remove(&pf->elem);
        free(pf);
        e = next;
    }
    lock_release(&filesys_lock);
}
```

Remember that `filesys_lock` is designed as a global lock. For all file operations, we need the lock in this project, including this one in `process.c`. Here, after acquire the lock, just like what we do for `child_list`, we traverse the list and close the files one by one.

#### Denying writes to running executables

As mentioned earlier, while a user program is running, the executable file it was loaded from must not be modified on disk. Therefore, we need an additional protection mechanism for the running executable. This logic is mainly implemented in `load`.

First, I add a new member `executable_file` to `struct thread` to record the executable file currently used by the process. In `load`, before opening and reading the executable, I use the global file system lock `filesys_lock` to protect the entire loading procedure. After the file is opened successfully, I call `file_deny_write` to prevent any writes to that executable while it is running, and store the file pointer in `t->executable_file`.

Concretely, I modify `load` as follows:

```c
    /* Open executable file. */
    lock_acquire(&filesys_lock);
    file = filesys_open(file_name);
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }
    file_deny_write(file);
    t->executable_file = file;
    ......
done:
    /* We arrive here whether the load is successful or not. */
    lock_release(&filesys_lock);
    return success;
```

When the process exits (in `process_exit`), we must restore the file to a normal state. So I allow writes again and then close the executable file:

```c
if (cur->executable_file != NULL) {
    file_allow_write(cur->executable_file);
    file_close(cur->executable_file);
}
```

With this protection, the executable cannot be corrupted while the program is running, and once the process terminates, the write permission is restored so the file can be modified or executed again in later runs.

#### `fork` with open files

Aha, it’s `fork` again! This syscall really gave me a headache.

`fork` creates a child process by copying the parent process. That means all file descriptors already opened by the parent should also appear in the child after `fork`. However, we **cannot** implement this by simply calling `open` again in the child: `open` creates a brand-new `struct file*` object for the same `inode`, while `fork` requires the parent and child to behave as if they are referring to the **same open file** (in particular, they should share the same file position).

Therefore, instead of reopening files, the child needs to inherit the parent’s `pfile` entries so that both processes’ file descriptors point to the same underlying `struct file *`.

This immediately leads to another problem: after `fork`, the parent and child run independently, so closing a file in one process must not break the other process. But in Pintos, `file_close` frees the `struct file` object and closes its `inode` immediately when there are no other opens of the file. If the parent and child share the same `struct file*` and both call `close`, then the first `close` would free the file structure, and the second process would later access freed memory, causing serious errors.

To solve this, we introduce a small optimization in `file.c`: we add a reference counter `ref` to `struct file` to track how many processes are currently sharing the same open file object.

- When a file is opened, `ref` is initialized to `1`, meaning only one process currently holds it.
- When `fork` duplicates the parent’s file descriptor entries, we increment `ref` for each shared `struct file*`.

Because Pintos emphasizes encapsulation and safety in the file system layer, I do not modify `ref` directly from outside. Instead, I provide a small API `file_ref_increase()` that updates `ref` safely, and call this API during `fork`.

The relevant code in `file.c` is:

```c
/* An open file. */
struct file {
    struct inode* inode; /* File's inode. */
    off_t pos;           /* Current position. */
    bool deny_write;     /* Has file_deny_write() been called? */
    int ref;             /* Reference count. */
};

/* Opens a file for the given INODE, of which it takes ownership,
   and returns the new file.  Returns a null pointer if an
   allocation fails or if INODE is null. */
struct file* file_open(struct inode* inode) {
    struct file* file = calloc(1, sizeof *file);
    if (inode != NULL && file != NULL) {
        file->inode = inode;
        file->pos = 0;
        file->deny_write = false;
        file->ref = 1;
        return file;
    } else {
        inode_close(inode);
        free(file);
        return NULL;
    }
}
void file_ref_increase(struct file* file) {
    ASSERT(file != NULL);
    file->ref++;
}
```

In `fork`, I copy the parent’s open file list into the child and increment the reference count for every shared file:

```c
/* Copy parent's file descriptors. */
if (success) {
    lock_acquire(&filesys_lock);
    struct list_elem* e;
    for (e = list_begin(&parent->open_files); e != list_end(&parent->open_files);
         e = list_next(e)) {
        struct pfile* parent_pf = list_entry(e, struct pfile, elem);
        struct file* file = parent_pf->file;
        struct pfile* child_pf = malloc(sizeof(struct pfile));
        if (child_pf == NULL || file == NULL) {
            success = false;
            lock_release(&filesys_lock);
            goto done;
        }
        file_ref_increase(file);
        child_pf->file = file;
        child_pf->fd = child->next_fd++;
        list_push_back(&child->open_files, &child_pf->elem);
    }
    lock_release(&filesys_lock);
}
```

Finally, we update the close logic. With reference counting, closing a file should only release the underlying `inode` and free the `struct file` when **no process is using it anymore**. If multiple processes still reference the file (`ref > 1`), we simply decrement the counter and return, leaving the file object valid for the remaining process:

```c
/* Closes FILE. */
void file_close(struct file* file) {
    if (file != NULL) {
        if (file->ref > 1) {
            file->ref--;
            return;
        }
        file_allow_write(file);
        inode_close(file->inode);
        free(file);
    }
}
```

With these changes, `fork` can correctly inherit open files from the parent (without reopening them), and `close` will not accidentally break the other process that still uses the same open file object.

## Summary by ChatGPT

This project extends Pintos with a complete user program support stack, focusing on correctness, safety, and well-defined process semantics.

- **Argument Passing**: Implemented a fully compliant initial user stack layout for `_start(argc, argv)`, including correct string placement, pointer construction, and **16-byte alignment**.
- **System Call Safety**: Built a robust syscall framework with **byte-by-byte argument fetching**, strict user pointer/string validation, and a fault-tolerant strategy that prevents malformed user pointers from crashing the kernel.
- **Process Lifecycle & Synchronization**: Introduced `struct child` to model parent–child relationships and used **two semaphores (`wait_sema`, `load_sema`)** to synchronize `exec/wait/exit/fork`, ensuring deterministic return behavior and correct status propagation.
- **Fork Support**: Implemented `fork` by copying the parent address space and execution context, guaranteeing the child observes `fork()` returning `0`.
- **File System Semantics**: Enforced executable write protection via `file_deny_write()` during execution, and implemented shared open-file inheritance across `fork` using **reference counting** to avoid double-close and preserve shared file position semantics.

Overall, the design prioritizes defensive memory handling, race-free parent/child coordination, and faithful Unix-like behavior for process and file operations.