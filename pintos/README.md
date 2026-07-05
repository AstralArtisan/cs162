# Pintos

This directory contains our implementation of Pintos, a small teaching
operating system used to study how kernel subsystems work together. The tasks
extend the starter kernel incrementally, with each project focusing on a
different part of process, thread, and resource management.

## Project Overview

- **User programs:** start user processes with correctly constructed stacks,
  cross the user-kernel boundary through system calls, manage parent-child
  process relationships, and provide safe file operations.
- **Threads:** replace timer busy waiting with blocking and wake-up scheduling,
  expose synchronization primitives to user programs, and support multiple
  user threads within one process.

Detailed implementation notes are maintained separately:

- [Project 1: User Programs](docs/Proj1.md)
- [Project 2: Threads](docs/Proj2.md)

## Work Scope

My work focuses on the kernel paths that connect user programs to Pintos
services and on the lifecycle of processes and threads. The main areas include:

- argument parsing, initial user-stack construction, and executable loading;
- safe user-memory access and system-call argument validation;
- process creation, waiting, forking, exit handling, and resource cleanup;
- file-descriptor management, file-system system calls, and executable
  write protection;
- timer-based thread sleeping without busy waiting;
- user-level lock and semaphore system calls and their kernel-side mappings;
- user-thread creation, startup, join, exit, and shared process state.

The implementation is under [`src/`](src/), while design notes, debugging
observations, and implementation details are collected under [`docs/`](docs/).
