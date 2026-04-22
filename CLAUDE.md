# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a CS 162 (Operating Systems) student repository. The primary work is in `group/`, which contains a Pintos teaching OS implementation. There are documents in `group/docs` for each project.

## Group Project: Pintos OS

The active, modified code lives in `group/src/userprog/` (process control, syscalls, pthreads) and `group/src/threads/` (scheduler, synchronization).

### Build

```bash
cd group/src/userprog && make          # Build userprog project
cd group/src/threads  && make          # Build threads project
make clean                              # Clean artifacts
make format                             # Apply clang-format
```

The kernel targets 32-bit x86. `Make.config` auto-detects the compiler and sets `-march=i686 -ggdb3 -O0 -fno-pic`.

### Run Tests

```bash
cd group/src/userprog && make check    # Run all userprog tests
cd group/src/threads  && make check    # Run all threads tests
cd group/src/userprog && make grade    # Show grade breakdown
```

Individual test (from the build directory after `make`):

```bash
cd group/src/userprog
pintos-test <test-name>
```

Debug individul test:
```bash
cd group/src/userprog
pintos-debug <test-name>
```

Test sources are in `group/src/tests/userprog/` and `group/src/tests/threads/`.

## Architecture: Pintos Userprog

### Key Data Structures (`group/src/userprog/process.h`)

- **`struct process`** (PCB) — one per process; contains page directory, child list, open file table, pthread bitmap, user-space lock/semaphore maps. All threads in a process share one PCB via `thread->pcb`.
- **`struct child`** — allocated by parent at `process_execute` time; tracks `exit_status`, `loaded`, and two semaphores (`wait_sema`, `load_sema`) for WAIT/EXEC synchronization. Owned by the parent's `child_list`.
- **`struct pfile`** — maps an `int fd` → `struct file*`; stored in `process->open_files`. FDs start at 2 (0 = stdin, 1 = stdout handled specially).
- **`struct pt`** — tracks a pthread (TID, exit status, join semaphore) in `process->pt_list`.
- **`struct lock_map` / `struct sema_map`** — map user-space opaque identifiers (`lock_t`/`sema_t`, which are `char`) to kernel `struct lock`/`struct semaphore` objects.

### Syscall Dispatch (`group/src/userprog/syscall.c`)

`syscall_handler` reads the syscall number from the user stack at `f->esp`, validates all user pointers with `check_user_vaddr()` / `get_user()` / `put_user()` before dereferencing, then dispatches. Any invalid access calls `thread_exit(-1)`.

Implemented syscalls: `EXIT`, `PRACTICE`, `HALT`, `EXEC`, `WAIT`, `FORK`, `CREATE`, `REMOVE`, `OPEN`, `READ`, `WRITE`, `SEEK`, `TELL`, `CLOSE`, `FILESIZE`, `LOCK_INIT`, `LOCK_ACQUIRE`, `LOCK_RELEASE`, `SEMA_INIT`, `SEMA_DOWN`, `SEMA_UP`, `PTHREAD_CREATE`, `PTHREAD_JOIN`, `PTHREAD_EXIT`.

### Process Lifecycle (`group/src/userprog/process.c`)

1. `process_execute` → allocates `struct child`, pushes it onto parent's `child_list`, spawns kernel thread running `start_process`.
2. `start_process` → loads ELF, sets up argument stack (16-byte aligned, right-to-left), initialises PCB, signals `load_sema`.
3. `process_exit` → closes all FDs, releases locks/semaphores, frees PCB structures, signals parent's `wait_sema`.
4. `process_wait` → finds child by PID in `child_list`, calls `sema_down(&child->wait_sema)`.

### Memory Safety Rules

- All user pointers must be `< PHYS_BASE` (`0xc0000000`) and mapped before use.
- Use `get_user(addr)` for byte reads from user space; use `put_user(addr, byte)` for writes.
- Never hold a lock while calling `sema_down` on a lock that another thread may need to acquire to release its semaphore (deadlock risk).

