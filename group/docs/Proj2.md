# Pintos proj2: Thread

[TOC]

In project 1, all we do is on user programs, and a "thread" is seemed to be the same as a "user process", with `pcb` in the thread structure. In project 2, we are going to focus on kernel threads, exploring how a multithread system works, and build the scheduler ourselves. We need to use `timer` as the clock of Pintos. With the `ticks` which timer gives us, we have the reference of scheduling.

## Efficient Alarm Clock

All timer-related operations are implemented in `devices/timer.c`. In this part, we need to modify `timer_sleep()` to avoid busy waiting, and take this opportunity to understand how the thread scheduling system works.

### Timer Overview

At the beginning of the project, we need to understand what the timer does and how it works. Let's examine the code:

- **`ticks`**: The number of timer ticks since the OS booted. When the OS starts, the timer begins to "tick" at a frequency of 100 ticks per second. In Pintos, we treat **ticks as the unit of time**.

- **interrupt:** All timer-related operations must be performed with interrupts disabled. This ensures that the OS cannot schedule another thread while we are reading or modifying timer data, which guarantees correctness.

  The way to disable interrupts in Pintos is:

  ```c
  enum intr_level old_level = intr_disable();
  ...
  intr_set_level(old_level);
  ```

  Here, we use `intr_set_level(old_level)` to restore the previous interrupt state. This is necessary because interrupts might already have been disabled before calling this code.

- **`timer_ticks()`**: Returns the number of timer ticks since the OS booted.

- **`timer_elapsed()`**: Returns the number of ticks elapsed since a given tick value, which should be obtained from `timer_ticks()`.

- **`timer_sleep(int64_t ticks)`**: Suspends the current thread for a specified number of timer ticks. Before the sleep duration expires, the thread cannot be scheduled. When the time expires, the thread must be moved to the ready queue and can be scheduled again.

- **`thread_tick()`**: This function is implemented in `thread.c`. It keeps track of tick statistics for idle, user, and kernel threads. If the current thread's time slice expires, it yields the CPU. This function is invoked by `timer_interrupt()`.

- **`timer_interrupt()`**: This function is invoked by the real timer hardware. On each timer tick, the OS updates the tick count and checks whether any sleeping threads need to be woken up.

In this part, we need to modify both `timer_sleep()` and `timer_interrupt()`.

### Work

In the original Pintos implementation, `timer_sleep()` uses busy waiting. As we have learned, busy waiting is inefficient and should be avoided. The core of our solution is a **priority queue implemented using a list**.

We define a global list called `wait_list` and maintain it in sorted order. Pintos provides the function:

```c
list_insert_ordered(struct list*, struct list_elem*, list_less_func*, void* aux)
```

which allows us to keep the list ordered. With this function, we can maintain the list as a priority queue based on wakeup time.

Let's look at the code:

```c
void timer_sleep(int64_t ticks) {
  int64_t start = timer_ticks();
  struct thread* cur = thread_current();

  ASSERT(intr_get_level() == INTR_ON);
  enum intr_level old_level = intr_disable();
  cur->wakeup_tick = start + ticks;
  list_insert_ordered(&wait_list, &cur->elem, (list_less_func*) &thread_compare_wakeup_tick, NULL);
  thread_block();
  intr_set_level(old_level);
}
```

We add a new field `wakeup_tick` to each thread and initialize it to `0`. This field records the tick at which the thread should wake up.

Interrupts must be enabled when calling this function, because blocking the current thread may trigger a context switch.

We first get the current time using `timer_ticks()`, then add the requested sleep duration and store the result in the thread's `wakeup_tick`.

Next, we insert the thread into `wait_list` using `list_insert_ordered()`, which keeps the list sorted. This ensures that the thread with the earliest wakeup time is at the front of the list.

Finally, we call `thread_block()` to block the thread and restore the interrupt state.



The comparator function `thread_compare_wakeup_tick` ensures that the list is sorted in ascending order of `wakeup_tick`:

```c
bool thread_compare_wakeup_tick(const struct list_elem* a, const struct list_elem* b, void* aux UNUSED) {
  struct thread* thread_a = list_entry(a, struct thread, elem);
  struct thread* thread_b = list_entry(b, struct thread, elem);
  return thread_a->wakeup_tick < thread_b->wakeup_tick;
}
```

This guarantees that the thread with the smallest `wakeup_tick` is always at the front of the list.



Every time a timer interrupt occurs, we need to check the `wait_list` and wake up any threads whose sleep time has expired.

```c
static void timer_interrupt(struct intr_frame* args UNUSED) {
  ticks++;
  thread_tick();
  /* Wake up any threads whose sleep has expired */
  while (!list_empty(&wait_list)) {
    struct list_elem* first_elem = list_front(&wait_list);
    struct thread* first_thread = list_entry(first_elem, struct thread, elem);
    if (first_thread->wakeup_tick <= ticks) {
      list_pop_front(&wait_list);
      thread_unblock(first_thread);
    } else {
      break;
    }
  }
}
```

We increment the global tick counter and call `thread_tick()`. Then, we repeatedly check the first thread in `wait_list`. Since the list is sorted, only the front thread needs to be checked. If its `wakeup_tick` is less than or equal to the current tick, we remove it from the list and unblock it. If not, we stop checking, because all remaining threads have later wakeup times.

------

## User threads

We chose to implement user threads first because this aligns closely with our work in Project 1, albeit requiring significant improvements to our initial implementation. In this section, we will build the system calls for a minimal `pthread` (Pintos thread) library, exposing robust synchronization primitives to user programs.

### User-level synchronization

Before constructing our `pthread` framework, we must establish user-level synchronization system calls. Our objective is to provide user programs with two fundamental synchronization tools: **locks** and **semaphores**.

Drawing on our experience from Project 1, we are already familiar with the underlying synchronization primitives provided by Pintos. Our task now is to design an interface that allows user processes to safely invoke kernel-level locks and semaphores, ensuring strict encapsulation and security.

To achieve this, we introduce two opaque, character-based types: `lock_t` and `sema_t`. The primary challenge moving forward is how to securely and accurately map these user-space types to the actual kernel lock and semaphore structures.

#### Syscall interface

As in Project 1, the first step in implementing a system call is to add a new case in `syscall_handler`. It is important to note that `lock_t*` and `sema_t*` are essentially `char*` from the kernel’s perspective. They represent user-level lock or semaphore objects stored in user memory. Their internal structure will be explained later.

- `bool lock_init(lock_t* lock)`: Initializes `lock` by registering it with the kernel, and returns true if the initialization was successful. In `syscall_handler`, it's implemented like below:

  ```c
  if (args[0] == SYS_LOCK_INIT) {
      get_args(f, args, 1);
      if (args[1] == 0) {
          f->eax = false;
      } else {
          check_user_vaddr((void*)args[1], true);
          f->eax = sys_lock_init((lock_t*)args[1]);
      }
  }
  ```

  ​	When the user attempts to initialize a lock, the pointer cannot be `NULL`. If it is `NULL`, we immediately return `false`. 	Since we need to write back some information into user memory (to associate the user lock with a kernel lock object), we must ensure the memory is writable. Therefore, when calling `check_user_vaddr`, we pass `true` for the `write` parameter.

  ​	During debugging, we discovered that our Project 1 implementation had issues when checking writability. The previous version could overwrite existing values during validation. We modified it to preserve the original value:

  ```c
  /* Checks if a user virtual address is valid. If not, terminates the
     process. If WRITE is true, checks if the user address is writable. */
  void check_user_vaddr(const void* vaddr, bool write) {
    if (!is_user_vaddr(vaddr))
      Exit(-1);
    if (write) {
      int old = get_user((const uint8_t*)vaddr);
      if (old == -1)
        Exit(-1);
      if (!put_user((uint8_t*)vaddr, (uint8_t)old))
        Exit(-1);
    } else {
      if (get_user((const uint8_t*)vaddr) == -1)
        Exit(-1);
    }
  }
  ```

- `void lock_acquire(lock_t* lock)`: Acquires `lock` and exits the process if acquisition failed. In `syscall_handler`, it's implemented like below:

  ```c
  if (args[0] == SYS_LOCK_ACQUIRE) {
      get_args(f, args, 1);
      check_user_vaddr((void*)args[1], true);
      f->eax = sys_lock_acquire((lock_t*)args[1]);
  }
  ```

  ​	Before invoking the kernel implementation, we validate the user pointer to ensure it is writable and valid. The actual lock acquisition logic is handled inside `sys_lock_acquire`, which maps the user-level lock to the corresponding kernel lock and invokes `lock_acquire()` internally.

- `void lock_release(lock_t* lock)`: Releases `lock`, and exits the process if the release failed. In `syscall_handler`, it's implemented like below:

  ```c
  if (args[0] == SYS_LOCK_RELEASE) {
      get_args(f, args, 1);
      check_user_vaddr((void*)args[1], true);
      f->eax = sys_lock_release((lock_t*)args[1]);
  }
  ```

  ​	Similarly, we validate the user pointer before calling the kernel-level release function. The actual release logic is performed inside `sys_lock_release`.

- `bool sema_init(sema_t* sema, int val)`: Initializes `sema` to `val` by registering it with the kernel, and returns true if the initialization was successful. In `syscall_handler`, it's implemented like below:

  ```c
  if (args[0] == SYS_SEMA_INIT) {
      get_args(f, args, 2);
      if (args[1] == 0) {
          f->eax = false;
      } else {
          check_user_vaddr((void*)args[1], true);
          f->eax = sys_sema_init((sema_t*)args[1], (int)args[2]);
      }
  }
  ```

  ​	If the user pointer is `NULL`, initialization fails immediately. Otherwise, we validate the address for write access and delegate the actual initialization to `sys_sema_init`.

- `void sema_down(sema_t* sema)`: Downs `sema` and exits the process if the down operation failed. In `syscall_handler`, it's implemented like below:

  ```c
  if (args[0] == SYS_SEMA_DOWN) {
      get_args(f, args, 1);
      check_user_vaddr((void*)args[1], true);
      f->eax = sys_sema_down((sema_t*)args[1]);
  }
  ```

  ​	We first validate the user pointer, then invoke the kernel-level `sys_sema_down`, which internally calls `sema_down()` on the associated kernel semaphore.

- `void sema_up(sema_t* sema)`: Ups `sema`, and exits the process if the up operation failed. In `syscall_handler`, it's implemented like below:

  ```c
  if (args[0] == SYS_SEMA_UP) {
      get_args(f, args, 1);
      check_user_vaddr((void*)args[1], true);
      f->eax = sys_sema_up((sema_t*)args[1]);
  }
  ```

  ​	As with other synchronization syscalls, we validate the user pointer and delegate the core logic to the corresponding kernel function.

Finishing these syscalls, we begin to dig in the core implementation of user-level synchronization.

#### Thoughts and Construction

The biggest challenge at this stage is how to bridge user space and kernel space through `lock_t` and `sema_t`. Before designing the mapping, we should first clarify why we use these two `char` types to represent locks and semaphores in user space.

As we know, a `char` consists of 8 bits, which allows it to represent up to 256 distinct values. In our design, these values serve as identifiers that establish a one-to-one mapping between user-level synchronization objects and their corresponding kernel-level implementations. Therefore, the core task here is to build and maintain this mapping correctly.

In our model, user-level synchronization primitives are managed at the **process level**, rather than the thread level. This means the process control block (`pcb`) must be extended to store the relevant synchronization metadata. We use locks as an example below; the design for semaphores is almost identical.

To associate a `lock_t` identifier with a real kernel `struct lock`, we introduce a wrapper structure `struct lock_map`, which binds them together. Since a process may create multiple locks, we maintain all user-created locks in a `struct list locks`, where each element is a `lock_map`.

Our allocation strategy treats `lock_t` as the unique identifier (ID) of a lock. When a new user lock is created, we assign it the next available ID and create a corresponding kernel `struct lock`. To support this, we add a field `lock_t next_lock` to `struct process`, which tracks the next ID to be allocated.

In addition, since lock-related system calls may be invoked concurrently by multiple threads within the same process, we introduce an internal kernel lock (`lock_protect`) inside `struct process` to ensure mutual exclusion when accessing or modifying the lock list. This prevents race conditions during lock creation, lookup, or removal.

```c
struct process {
    ...
    struct list locks;          /* Locks held by the process */
    lock_t next_lock;         /* Next lock identifier */
    struct lock lock_protect;
    ...
};
/* Maps locks to their identifiers for a process. */
struct lock_map {
    lock_t id;
    struct lock* lock;
    struct list_elem elem;
};
```

With this structure, we can safely translate a user-provided `lock_t` into its corresponding kernel lock, while maintaining isolation and correctness between user space and kernel space.

#### Implementation: Lock

With our data structures in place, we can now implement the core logic that bridges user-space lock identifiers (`lock_t`) with their kernel-space counterparts.

- `sys_lock_init`: This system call initializes a new user-level lock and registers it with the kernel. Let's see the code first:

  ```c
  bool sys_lock_init(lock_t* lock) {
    struct process* p = thread_current()->pcb;
    if (p == NULL) {
      return false;
    }
    struct lock_map* lock_map = malloc(sizeof(struct lock_map));
    if (lock_map == NULL) {
      return false;
    }
    lock_map->lock = malloc(sizeof(struct lock));
    if (lock_map->lock == NULL) {
      free(lock_map);
      return false;
    }
    lock_init(lock_map->lock);
    lock_acquire(&p->lock_protect);
    if (p->next_lock == 0) {
      lock_release(&p->lock_protect);
      free(lock_map->lock);
      free(lock_map);
      return false;
    }
    lock_map->id = p->next_lock++;
    list_push_back(&p->locks, &lock_map->elem);
    lock_release(&p->lock_protect);
  
    if (!put_user((uint8_t*)lock, (uint8_t)lock_map->id)) {
      lock_acquire(&p->lock_protect);
      list_remove(&lock_map->elem);
      lock_release(&p->lock_protect);
      free(lock_map->lock);
      free(lock_map);
      return false;
    }
    return true;
  }
  ```

  ​	When a user process requests to initialize a lock, the kernel must create a new kernel-level `struct lock` and establish the mapping between this lock and a user-visible `lock_t` identifier.

  ​	First, we obtain the current process from `thread_current()->pcb`. Since user-level synchronization is managed at the process level, if the process control block is `NULL`, the initialization immediately fails and returns `false`.

  ​	The core of this system call lies in **establishing the mapping** and **securely returning the ID**:

  - **Assigning the Identifier:** We use the process's `next_lock` field as an ID generator. Because multiple threads might try to initialize locks simultaneously, we acquire `p->lock_protect` to ensure mutual exclusion. We treat `0` as an invalid or exhausted state; if `next_lock` wraps around to `0` (a char type 11111111 + 1 returns 00000000), we know we have run out of identifiers, so we release the lock, free the memory, and abort. Otherwise, we stamp the `lock_map` with the current `next_lock` ID, increment the counter, push the mapping onto the process's `locks` list, and release our protection lock.
  - **The `put_user` Hand-off and Rollback:** The most delicate step is handing this newly generated ID back to user space. We cannot blindly trust user pointers, so we rely on `put_user` to safely write the 8-bit ID to the user's `lock_t*` address.
  - **Handling User-Space Failures:** If `put_user` fails—meaning the user provided an invalid, unmapped, or read-only pointer—we must perform a strict **rollback**. We re-acquire `lock_protect`, explicitly remove the newly added mapping from the `locks` list, free both the kernel lock and the map structure, and return `false`. This rollback guarantees that a buggy user program cannot trick the kernel into leaking memory or maintaining "ghost" locks.

  ​	If all these steps succeed, the function returns `true`, confirming that the user-level lock is successfully registered and ready for use.

- `sys_lock_acquire`: This system call attempts to acquire a previously initialized user-level lock. Let's see the code first:

  ```c
  bool sys_lock_acquire(lock_t* lock) {
    lock_t id = (lock_t)get_user((const uint8_t*)lock);
    if (id == (lock_t)-1)
      return false;
    struct lock* klock = find_lock(id);
    if (klock == NULL)
      return false;
    if (lock_held_by_current_thread(klock))
      return false;
    lock_acquire(klock);
    return true;
  }
  ```

  ​	When a user process requests to acquire a lock, the kernel must safely read the lock identifier from user space, resolve it to the corresponding kernel lock, and ensure it is safe to acquire.

  ​	The core of this system call lies in safely validating the user's request and preventing internal kernel deadlocks:

  - **Secure ID Retrieval:** We cannot directly dereference the user's `lock_t*` pointer. Instead, we rely on `get_user` to safely read the 8-bit ID from user memory. If `get_user` fails (returning `-1` because the pointer is invalid or unmapped), we immediately return `false`.

  - **Mapping Lookup via `find_lock`:** Once we have a valid ID, we must find its matching kernel structure. We pass the ID to `find_lock(id)`. This helper function retrieves the current process's PCB and iterates through the process's `locks` list. Crucially, we wrap this list traversal in `lock_acquire(&p->lock_protect)` and `lock_release(&p->lock_protect)`. This ensures that if other threads in the same process are initializing or destroying locks simultaneously, our list traversal will not be corrupted by concurrent modifications. If the loop finishes and returns `NULL`, it means the user provided an ID that does not map to any initialized lock, so we abort the operation.

    ```c
    /* Finds the lock associated with the given lock identifier. */
    struct lock* find_lock(lock_t id) {
      struct process* p = thread_current()->pcb;
      if (p == NULL) {
        return NULL;
      } 
      struct list_elem* e;
      struct lock* lock = NULL;
      lock_acquire(&p->lock_protect);
      for (e = list_begin(&p->locks); e != list_end(&p->locks); e = list_next(e)) {
        struct lock_map* lock_map = list_entry(e, struct lock_map, elem);
        if (lock_map->id == id) {
          lock = lock_map->lock;
          break;
        }
      }
      lock_release(&p->lock_protect);
      return lock;
    }
    ```

  - **Deadlock Prevention:** Pintos locks do not support recursive acquisition by default. If a thread attempts to acquire a lock it already holds, it will deadlock. To prevent a buggy user program from freezing a kernel thread, we explicitly check `lock_held_by_current_thread(klock)`. If the thread already owns the lock, we return `false`.

  ​	If all checks pass, we call the kernel's native `lock_acquire(klock)`. The function then returns `true`, indicating the thread now successfully holds the lock.

- `sys_lock_release`: This system call releases a user-level lock that the current thread holds. Let's see the code first:

  ```c
  bool sys_lock_release(lock_t* lock) {
    lock_t id = (lock_t)get_user((const uint8_t*)lock);
    if (id == (lock_t)-1)
      return false;
    struct lock* klock = find_lock(id);
    if (klock == NULL)
      return false;
    if (!lock_held_by_current_thread(klock))
      return false;
    lock_release(klock);
    return true;
  }
  ```

  ​	When releasing a lock, the kernel's primary responsibility is strict ownership verification. A thread must never be allowed to release a lock it does not currently own.

  ​	The logic closely mirrors acquisition, with a crucial difference in the security checks:

  - **Secure ID Retrieval and Lookup:** Just like in `sys_lock_acquire`, we safely fetch the identifier using `get_user` and resolve it to a kernel lock using `find_lock(id)`. Any failure here results in returning `false`.
  - **Ownership Verification:** This is the most critical security step in the release process. A malicious or buggy thread might try to unlock a resource currently held by another thread, which would corrupt synchronization. We enforce strict ownership by checking `!lock_held_by_current_thread(klock)`. If the current thread is *not* the owner, we reject the request and return `false`.

  ​	Once ownership is verified, we safely call the kernel's `lock_release(klock)`. The function returns `true` to confirm the lock has been successfully released.

#### Implementation: Semaphore

With our lock implementation complete, handling user-level semaphores (`sema_t`) is a very straightforward process. The underlying architecture—allocating a mapping structure, generating an ID, securely handling user pointers with `get_user`/`put_user`, and rolling back on failure—is virtually identical to our lock implementation.

Let's look at the code:

```c
/* Finds the semaphore associated with the given semaphore identifier. */
struct semaphore* find_sema(sema_t id) {
  struct process* p = thread_current()->pcb;
  if (p == NULL) {
    return NULL;
  }
  struct list_elem* e;
  struct semaphore* sema = NULL;
  lock_acquire(&p->sema_protect);
  for (e = list_begin(&p->semaphores); e != list_end(&p->semaphores); e = list_next(e)) {
    struct sema_map* sema_map = list_entry(e, struct sema_map, elem);
    if (sema_map->id == id) {
      sema = sema_map->sema;
      break;
    }
  }
  lock_release(&p->sema_protect);
  return sema;
}

bool sys_sema_init(sema_t* sema, int val) {
  struct process* p = thread_current()->pcb;
  if (p == NULL || sema == NULL) {
    return false;
  }
  if (val < 0) {
    return false;
  }

  struct sema_map* sema_map = malloc(sizeof(struct sema_map));
  if (sema_map == NULL) {
    return false;
  }
  sema_map->sema = malloc(sizeof(struct semaphore));
  if (sema_map->sema == NULL) {
    free(sema_map);
    return false;
  }
  sema_init(sema_map->sema, (unsigned)val);

  lock_acquire(&p->sema_protect);
  if (p->next_sema == 0) {
    lock_release(&p->sema_protect);
    free(sema_map->sema);
    free(sema_map);
    return false;
  }
  sema_map->id = p->next_sema++;
  list_push_back(&p->semaphores, &sema_map->elem);
  lock_release(&p->sema_protect);

  if (!put_user((uint8_t*)sema, (uint8_t)sema_map->id)) {
    lock_acquire(&p->sema_protect);
    list_remove(&sema_map->elem);
    lock_release(&p->sema_protect);
    free(sema_map->sema);
    free(sema_map);
    return false;
  }
  return true;
}

bool sys_sema_down(sema_t* sema) {
  sema_t id = (sema_t)get_user((const uint8_t*)sema);
  if (id == (sema_t)-1) {
    return false;
  }
  struct semaphore* ksema = find_sema(id);
  if (ksema == NULL) {
    return false;
  }
  sema_down(ksema);
  return true;
}

bool sys_sema_up(sema_t* sema) {
  sema_t id = (sema_t)get_user((const uint8_t*)sema);
  if (id == (sema_t)-1) {
    return false;
  }
  struct semaphore* ksema = find_sema(id);
  if (ksema == NULL) {
    return false;
  }
  sema_up(ksema);
  return true;
}
```

Because the logic maps so closely to our lock implementation, we will not re-explain the entire flow. Instead, we highlight the three critical differences:

- **Initial Value Validation:** Unlike locks (which are strictly binary and initialize to an "unlocked" state), semaphores require an initial value. `sys_sema_init` accepts an `int val` parameter. Semaphores cannot have a negative initial value, so we must add a check: `if (val < 0) return false;`. Once validated, we pass this value to the kernel's `sema_init`.
- **Distinct Tracking Resources:** To keep locks and semaphores decoupled, semaphores use their own dedicated tracking fields in the PCB: `p->semaphores` (the list), `p->next_sema` (the ID generator), and `p->sema_protect` (the mutual exclusion lock protecting the list).
- **No Ownership Verification:** The most significant behavioral difference is found in `sys_sema_down` and `sys_sema_up`. Notice that these functions are actually *simpler* than `sys_lock_acquire` and `sys_lock_release`. Because semaphores do not have a strict "owner" thread, we do not need to perform checks like `lock_held_by_current_thread(klock)`. Any thread can "up" a semaphore to signal an event, and multiple threads can "down" a semaphore without causing the type of recursive deadlock seen with standard mutexes.

Now we already finish user-level synchronization. Next, we will see how we can build user threads based on all our previous work.

### Pthread

In `lib/user/pthread.h`, Pintos gives us a small `pthread` library, serving as the glue between the high-level API and the low-level system call, with the function of `pthread_create`, `pthread_exit`, and `pthread_join`. Before talking about the implementation details, we must understand how pthread works.

#### Pthread library

Let's see the basic construction of pthread library:

```c
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);
typedef int tid_t;
#define TID_ERROR ((tid_t)-1)

/* OS jumps to this function when a new thread is created.
   OS is required to setup the stack for this function and
   set %eip to point to the start of this function */
void _pthread_start_stub(pthread_fun fun, void* arg) {
  (*fun)(arg);    // Invoke the thread function
  pthread_exit(); // Call pthread_exit
}
```

There are two special functions here we need to learn about: `stub_fun` and `pthread_fun`. A `pthread_fun` is a function that controls the creation of a thread. A `stub_fun` is a stub function for OS to jump in at the beginning of creating a new thread. If we call the `pthread_fun` straightly without calling the `stub_fun`, we can't make sure that the thread exits correctly when it terminates. So, when we tries to create a new user thread, OS first traps into `_pthread_start_stub`, then goes into the real `pthread_fun`.

Then, we can see the specific function we need to build:

```c
/* Creates a new thread running fun with the given arg.
   Calls pthread_exit when the function completes.
   Returns TID of created thread or TID_ERROR on error */
tid_t pthread_create(pthread_fun fun, void* arg) {
  return sys_pthread_create(_pthread_start_stub, fun, arg);
}

/* Exits the current thread, and cleans up resources */
void pthread_exit() {
  sys_pthread_exit();
  NOT_REACHED();
}

/* Waits for thread TID to finish executing before returning.
   Returns false if an error occurred. */
bool pthread_join(tid_t tid) { return sys_pthread_join(tid) != TID_ERROR; }
```

When user calls the system call, OS first goes into these library functions, then goes to the syscall functions we are going to build soon.

#### `pthread_create`

`tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg)`

The `sys_pthread_create` function creates a new thread to run `stub_fun sfun`, and gives it as arguments a `pthread_fun` and a `void*` pointer, which is intended to be the argument of the `pthread_fun`. It returns to the parent the TID of the created thread, or `TID_ERROR` if the thread could not be created. It's of course that we should add this syscall to our `syscall_handler` first:

```c
if (args[0] == SYS_PT_CREATE) {
    get_args(f, args, 3);
    if (args[1] == 0 || args[2] == 0) {
        Exit(-1);
    }
    check_user_vaddr((const void*)args[1], false);
    check_user_vaddr((const void*)args[2], false);
    if (args[3] != 0) {
        check_user_vaddr((const void*)args[3], false);
    }
    f->eax = sys_pthread_create((stub_fun)args[1], (pthread_fun)args[2], (const void*)args[3]);
}
```

Note that this syscall has three `void*` type parameters, we need to check them one by one. If the syscall handler don't get any functions, it will exit immediately.

 For `sys_pthread_create`, it's just a bridge to `process.c`. The next work will go on there.

```c
tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg) {
    return pthread_execute(sfun, tfun, arg);
}
```

As we did for process, when we create a new thread, we need to set up a space of stack for it first.

The first question to settle is: what layout rule should we follow when allocating thread stacks? Our approach assigns each user thread a fixed slot of one page (`STACK_SIZE = PGSIZE`) and places the slots consecutively downward from `PHYS_BASE`. Every thread stack is identified by a **thread number** (`tnum`); the process's main thread always occupies slot 0. Given a `tnum`, we can immediately calculate the top address of that slot with `stack_top()`. This design also has a clear upgrade path: if virtual memory support is added later, only these helpers need to change.

```c
/* stack helpers */
/* If includes vm, this piece of code needs a big change. */
#define STACK_PAGES 1
#define STACK_SIZE (STACK_PAGES * PGSIZE)

/* User stack slot mapping:
   tnum == 0 is the main thread stack at top of user address space. */
static void* stack_top(int tnum) { return (void*)(PHYS_BASE - tnum * STACK_SIZE); }
```

Since the process must track all of its threads, we need a data structure to record and manage the state of each thread slot. We chose a **bitmap** for this purpose. A bitmap is essentially an array of bits: a `1` at position `i` means slot `i` is currently occupied by a live thread, while a `0` means the slot is free and can be assigned to the next new thread. Because `thread_bitmap` is shared among all threads of the process, any access or modification must be protected by `thread_lock` to prevent race conditions. This is reflected in the two stack management helpers:

```c
static int alloc_stack(struct process* p) {
  lock_acquire(&p->thread_lock);
  /* Slot 0 is reserved for the main thread. */
  size_t idx = bitmap_scan_and_flip(p->thread_bitmap, 1, 1, false);
  lock_release(&p->thread_lock);
  if (idx == BITMAP_ERROR)
    return -1;
  return (int)idx;
}

static void free_stack(struct process* p, int tnum) {
  lock_acquire(&p->thread_lock);
  if (tnum > 0)
    bitmap_set(p->thread_bitmap, tnum, false);
  lock_release(&p->thread_lock);
}
```

`alloc_stack` calls `bitmap_scan_and_flip`, scanning from slot 1 (slot 0 is permanently reserved for the main thread). This function atomically finds the first `false` bit and flips it to `true`, returning its index. The atomicity eliminates any time-of-check/time-of-use race — no other thread can claim the same slot between the scan and the flip. If all slots are occupied, `BITMAP_ERROR` is returned and we propagate `-1` to the caller.

`free_stack` is the symmetric counterpart: it clears the bit for the given `tnum`. The `tnum > 0` guard ensures we never accidentally release the main thread's slot.

The bitmap itself is initialized in `init_pcb`:

```c
pcb->thread_bitmap = bitmap_create(MAX_THREADS);
bitmap_set_all(pcb->thread_bitmap, false);
if (pcb->thread_bitmap != NULL)
  bitmap_set(pcb->thread_bitmap, 0, true);  /* reserve slot 0 for main */
lock_init(&pcb->thread_lock);
list_init(&pcb->pt_list);
```

#### `struct pt` and helper functions

While the bitmap tracks which stack *slots* are in use, we also need to track the lifecycle of each *thread* — specifically, whether it has exited and whether another thread is waiting to join it. For this we introduce `struct pt`:

```c
struct pt {
  tid_t tid;               /* kernel TID of this thread */
  bool exited;             /* true once pthread_exit() has been called */
  bool joined;             /* true once a joiner has claimed this slot */
  int tnum;                /* stack slot index */
  struct semaphore wait_sema; /* joiner waits here */
  struct list_elem elem;
};
```

Every user thread — including the process's main thread — owns exactly one `struct pt`. All `pt` entries for a process are collected in `p->pt_list`, protected by `p->thread_lock`.

Two small helpers manage these structures:

```c
static struct pt* pt_init() {
  struct pt* t = malloc(sizeof(struct pt));
  if (t == NULL)
    return NULL;
  t->tid = TID_ERROR;
  t->exited = false;
  t->joined = false;
  t->tnum = -1;
  sema_init(&t->wait_sema, 0);
  return t;
}

static struct pt* find_pthread_locked(struct process* p, tid_t tid) {
  if (p == NULL)
    return NULL;
  struct list_elem* e;
  for (e = list_begin(&p->pt_list); e != list_end(&p->pt_list); e = list_next(e)) {
    struct pt* t = list_entry(e, struct pt, elem);
    if (t->tid == tid)
      return t;
  }
  return NULL;
}
```

`pt_init` allocates and zero-initializes a fresh `struct pt`. The `wait_sema` starts at 0 so that any call to `sema_down` on it will block immediately — the joiner can only proceed after the thread itself calls `sema_up` from `pthread_exit`.

`find_pthread_locked` performs a linear scan of `pt_list`. The name suffix `_locked` signals that the caller must already hold `p->thread_lock` before calling this function.

The main thread's `struct pt` is registered during `start_process`, right after the ELF is loaded successfully:

```c
if (success) {
  struct pt* pt = pt_init();
  if (pt == NULL) {
    success = false;
  } else {
    pt->tid = t->tid;
    pt->tnum = 0;
    lock_acquire(&t->pcb->thread_lock);
    list_push_back(&t->pcb->pt_list, &pt->elem);
    lock_release(&t->pcb->thread_lock);
  }
}
```

This ensures that the main thread is treated uniformly with every other user thread, which simplifies `pthread_exit_main` considerably.

#### `setup_thread`

Before a new kernel thread can execute user code, it needs its own user-space stack populated with the correct arguments. This is handled by `setup_thread`:

```c
bool setup_thread(void (**eip)(void), void** esp,
                  stub_fun sf, pthread_fun tf, void* arg,
                  int tnum) {
  bool success = false;
  struct process* p = thread_current()->pcb;
  if (p == NULL)
    return false;

  uint8_t* sp = (uint8_t*)stack_top(tnum);
  uint8_t* upages[STACK_PAGES];
  uint8_t* kpages[STACK_PAGES];
  int mapped = 0;
  for (int i = 0; i < STACK_PAGES; i++) {
    uint8_t* kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage == NULL)
      goto fail;
    uint8_t* upage = sp - (i + 1) * PGSIZE;
    success = install_page(upage, kpage, true);
    if (!success) {
      palloc_free_page(kpage);
      goto fail;
    }
    upages[mapped] = upage;
    kpages[mapped] = kpage;
    mapped++;
  }

  uint8_t* kpage = kpages[0];
  uint8_t* bottom = upages[0];
  *eip = (void (*)(void))sf;

  /* Stack align. */
  uintptr_t want = (uintptr_t)sp - 3 * sizeof(void*);
  size_t pad = want & 0xF;
  sp -= pad;
  memset(kpage + (sp - bottom), 0, pad);

  sp -= sizeof(void*);
  void* tmp_arg = arg;
  memcpy(kpage + (sp - bottom), &tmp_arg, sizeof(void*)); // Push void* arg

  sp -= sizeof(void*);
  void* tmp_tf = (void*)tf;
  memcpy(kpage + (sp - bottom), &tmp_tf, sizeof(void*)); // Push pthread_fun tf

  sp -= sizeof(void*);
  memset(kpage + (sp - bottom), 0, sizeof(void*));       // Push fake return address

  *esp = (void*)sp;
  return true;

fail:
  for (int i = 0; i < mapped; i++) {
    pagedir_clear_page(p->pagedir, upages[i]);
    palloc_free_page(kpages[i]);
  }
  return false;
}
```

The function performs two logically distinct tasks:

**1. Page allocation and mapping.** We allocate `STACK_PAGES` physical pages from the user pool and map them into the process's page directory at the addresses dictated by the slot. All pages are zero-initialized (`PAL_ZERO`) to avoid information leakage between threads. If any allocation or mapping fails, we roll back all previously mapped pages before returning `false`.

**2. Argument layout on the stack.** Once the pages are mapped, we lay out the initial stack frame that `_pthread_start_stub` expects:

```
high address  ─────────────────────────
              │  void* arg             │  ← pushed first (higher address)
              │  pthread_fun tf        │
              │  fake return address   │  ← ESP points here on entry
low address   ─────────────────────────
```

A crucial detail is the 16-byte alignment requirement. x86 calling conventions require that `%esp` be 16-byte aligned at the point of a `call` instruction. We compute the alignment padding needed after all three words have been pushed, then zero the pad bytes and adjust `sp` accordingly before laying down the arguments. Alignment is computed on the *intended final* `sp` (i.e., after subtracting three pointer widths), so the effective `%esp` upon entry to `_pthread_start_stub` satisfies the ABI.

The `eip` output parameter is set to `sf` (the stub function), which is where execution begins when the kernel returns to user space.

#### `pthread_execute`

`pthread_execute` is the main entry point for thread creation in the kernel. It orchestrates allocation, kernel-thread creation, and synchronization with the newly spawned thread:

```c
tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) {
  tid_t tid;
  struct process* p = thread_current()->pcb;
  if (p == NULL)
    return TID_ERROR;

  struct pt* t = pt_init();
  if (t == NULL)
    return TID_ERROR;

  struct start_helper* exec_ = malloc(sizeof(struct start_helper));
  if (exec_ == NULL) {
    free(t);
    return TID_ERROR;
  }
  exec_->t = t;
  exec_->sf = sf;
  exec_->tf = tf;
  exec_->arg = arg;

  int tnum = alloc_stack(p);
  if (tnum == -1) {
    free(t);
    free(exec_);
    return TID_ERROR;
  }
  exec_->p = p;
  exec_->t->tnum = tnum;
  sema_init(&exec_->load_sema, 0);
  exec_->loaded = false;

  tid = thread_create("pthread", PRI_DEFAULT, start_pthread, (void*)exec_);
  if (tid == TID_ERROR) {
    free_stack(p, tnum);
    free(t);
    free(exec_);
    return TID_ERROR;
  }
  exec_->t->tid = tid;
  lock_acquire(&p->thread_lock);
  list_push_back(&p->pt_list, &exec_->t->elem);
  lock_release(&p->thread_lock);

  sema_down(&exec_->load_sema);
  if (!exec_->loaded) {
    lock_acquire(&p->thread_lock);
    list_remove(&exec_->t->elem);
    lock_release(&p->thread_lock);
    tid = TID_ERROR;
    free_stack(p, tnum);
    free(t);
  }
  free(exec_);
  return tid;
}
```

The flow mirrors what `process_execute` does for full processes:

- **Allocate tracking structures.** We call `pt_init()` for the `struct pt` and `malloc` a `start_helper` to pass all arguments to the new kernel thread.
- **Claim a stack slot.** `alloc_stack` atomically finds and reserves a free `tnum` in the bitmap. If the process already has `MAX_THREADS` alive, this returns `-1` and we abort.
- **Spawn the kernel thread.** `thread_create("pthread", PRI_DEFAULT, start_pthread, exec_)` creates the kernel thread. If it fails (e.g., out of kernel memory), we undo all prior allocations.
- **Register and wait.** We assign the TID to `exec_->t->tid` and add the `struct pt` to `pt_list` *before* waiting on `load_sema`. This ordering is intentional: it ensures that `find_pthread_locked` can find the new entry even if the child thread is scheduled immediately and attempts to look itself up.
- **Check load result.** After `load_sema` is signaled by `start_pthread`, we inspect `exec_->loaded`. If the stack setup failed, we remove the `struct pt` from `pt_list`, free the stack slot, and return `TID_ERROR`. Either way, `exec_` (the helper struct) is always freed here by the parent, because the child is done with it by the time `load_sema` is signaled.

#### `start_pthread`

`start_pthread` is the kernel-thread body that runs in the newly created thread:

```c
static void start_pthread(void* exec_) {
  struct start_helper* exec = (struct start_helper*)exec_;
  stub_fun sf = exec->sf;
  pthread_fun tf = exec->tf;
  void* arg = exec->arg;
  struct thread* t = thread_current();
  t->pcb = exec->p;
  struct intr_frame if_;
  bool success;

  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  process_activate();

  success = setup_thread(&if_.eip, &if_.esp, sf, tf, arg, exec->t->tnum);
  if (!success) {
    exec->loaded = false;
    sema_up(&exec->load_sema);
    thread_exit();
  }
  exec->loaded = true;
  sema_up(&exec->load_sema);
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}
```

The structure is almost identical to `start_process`. Key points:

- **PCB attachment.** The very first action is `t->pcb = exec->p`, which binds the new kernel thread to the parent process's PCB. This must happen before `process_activate()` so that the correct page directory is loaded.
- **`process_activate()`.** Activates the process's page directory so that the new thread shares the same virtual address space as all other threads in the process.
- **`setup_thread`.** Allocates the user-space stack page, maps it into the page directory, and arranges the arguments. On failure, we signal `load_sema` with `loaded = false` and call `thread_exit()` to clean up the kernel thread.
- **Jump to user space.** On success, we signal `load_sema` with `loaded = true` (releasing the parent from its wait) and then jump to user space using the same `intr_exit` trick used in `start_process`. At this point execution continues at `sf` (i.e., `_pthread_start_stub`) with `tf` and `arg` on the user stack.

#### `pthread_join`

`pthread_join` waits for a target thread to exit and then reclaims its resources:

```c
tid_t pthread_join(tid_t tid) {
  struct process* p = thread_current()->pcb;
  if (p == NULL || tid == thread_current()->tid)
    return TID_ERROR;

  lock_acquire(&p->thread_lock);
  struct pt* t = find_pthread_locked(p, tid);
  if (t == NULL || t->joined) {
    lock_release(&p->thread_lock);
    return TID_ERROR;
  }
  t->joined = true;
  bool exited = t->exited;
  lock_release(&p->thread_lock);

  if (!exited)
    sema_down(&t->wait_sema);

  lock_acquire(&p->thread_lock);
  t = find_pthread_locked(p, tid);
  if (t == NULL) {
    lock_release(&p->thread_lock);
    return TID_ERROR;
  }
  int tnum = t->tnum;
  list_remove(&t->elem);
  lock_release(&p->thread_lock);

  if (tnum != 0) {
    free_stack_pages(p, tnum);
    free_stack(p, tnum);
  }
  free(t);
  return tid;
}
```

The implementation carefully handles several failure modes:

- **Self-join.** A thread joining on its own TID would deadlock forever. We detect this with `tid == thread_current()->tid` and immediately return `TID_ERROR`.
- **Non-existent or already-joined thread.** `find_pthread_locked` returns `NULL` if the TID is not in `pt_list`. We also check `t->joined` — a second join on the same thread is an error. We set `t->joined = true` while still holding `thread_lock` to ensure only one joiner can claim the slot.
- **Race-free exit check.** We snapshot `t->exited` under `thread_lock`, then release the lock before potentially blocking on `sema_down`. If the thread already exited before we checked, we skip the semaphore and proceed directly to cleanup.
- **Resource reclamation.** After the wait, we remove the `struct pt` from `pt_list`, then free the user-space stack pages via `free_stack_pages` and release the bitmap slot via `free_stack`. The main thread's slot (`tnum == 0`) is deliberately skipped — the initial stack is part of the process image and should not be unmapped while the process is still running.

#### `pthread_exit`

`pthread_exit` is called when a non-main user thread wishes to terminate:

```c
void pthread_exit(void) {
  struct thread* cur = thread_current();
  struct process* p = cur->pcb;
  if (p == NULL)
    goto exit;
  if (is_main_thread(cur, p)) {
    if (p->child_process != NULL)
      p->child_process->exit_status = 0;
    pthread_exit_main();
  }

  lock_acquire(&p->thread_lock);
  struct pt* t = find_pthread_locked(p, cur->tid);
  if (t != NULL) {
    t->exited = true;
    sema_up(&t->wait_sema);
  }
  lock_release(&p->thread_lock);
exit:
  thread_exit();
  NOT_REACHED();
}
```

For a non-main thread, the logic is straightforward: find the thread's own `struct pt`, set `exited = true`, and signal `wait_sema` so any waiting joiner can wake up and reclaim resources. Then call `thread_exit()` to destroy the kernel thread.

The main thread receives special treatment: if `is_main_thread` is true, we set the exit status to 0 (the default for a clean `pthread_exit`) and delegate to `pthread_exit_main`. This check exists because a user program calling `pthread_exit()` from the main thread should not leave the process in an inconsistent state — all other threads must be waited on first.

#### `pthread_exit_main`

`pthread_exit_main` handles the more complex case where the main thread is the one exiting:

```c
void pthread_exit_main(void) {
  struct thread* cur = thread_current();
  struct process* p = cur->pcb;
  if (p == NULL)
    return;

  lock_acquire(&p->thread_lock);
  struct pt* self = find_pthread_locked(p, cur->tid);
  if (self != NULL) {
    self->exited = true;
    sema_up(&self->wait_sema);
  }
  lock_release(&p->thread_lock);

  /* Wait until no other user thread remains in this process. */
  while (true) {
    tid_t target;
    lock_acquire(&p->thread_lock);
    target = pick_other_thread_locked(p, cur->tid);
    lock_release(&p->thread_lock);

    if (target == TID_ERROR)
      break;

    if (pthread_join(target) == TID_ERROR)
      thread_yield();
  }

  process_exit();
  NOT_REACHED();
}
```

The key invariant this function enforces is: **the process must not exit until every user thread has terminated**. Violating this would leave dangling kernel threads pointing at a freed PCB.

The implementation proceeds in two phases:

1. **Signal self.** The main thread marks its own `struct pt` as exited and signals its `wait_sema`. This allows any thread that called `pthread_join(main_tid)` to wake up and proceed. It is important to do this *before* the drain loop, because one of the remaining threads might be blocked in `pthread_join(main_tid)` and would otherwise deadlock.

2. **Drain all other threads.** We repeatedly call `pick_other_thread_locked` to find any thread in `pt_list` that is not the current thread. For each such thread, we call `pthread_join(target)`. If `pthread_join` returns `TID_ERROR` (which can happen if the thread was already joined by someone else, e.g., a child thread called `pthread_join` on it), we yield the CPU and retry the outer loop rather than busy-looping. The loop exits only when `pick_other_thread_locked` returns `TID_ERROR`, meaning `pt_list` contains only the main thread itself.

3. **Exit the process.** Once all threads are drained, we call `process_exit()`, which tears down the address space and signals the parent process.

---

With these components in place — stack slot management, `struct pt` lifecycle tracking, `setup_thread` for argument layout, `pthread_execute`/`start_pthread` for creation, and `pthread_join`/`pthread_exit`/`pthread_exit_main` for termination — the pthread subsystem is complete.

