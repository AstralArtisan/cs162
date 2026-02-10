#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include <string.h>
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler(struct intr_frame* f);
static int get_user(const uint8_t* uaddr);
static bool put_user(uint8_t* udst, uint8_t byte);
void check_user_vaddr(const void* vaddr, bool write);
void check_user_string(const char* str);
void check_user_buffer(const void* buffer, unsigned size, bool write);
uint32_t get_syscall_number(struct intr_frame* f);
void get_args(struct intr_frame* f, uint32_t* args, int num);
void Exit(int status);
pid_t fork(struct intr_frame* f);
bool create(const char* file, unsigned initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void* buffer, unsigned size);
int write(int fd, const void* buffer, unsigned size);
void seek(int fd, unsigned position);
int tell(int fd);
void close(int fd);
tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg);
void sys_pthread_exit(void);
tid_t sys_pthread_join(tid_t tid);
bool sys_lock_init(lock_t* lock);
bool sys_lock_acquire(lock_t* lock);
bool sys_lock_release(lock_t* lock);
bool sys_sema_init(sema_t* sema, int val);
bool sys_sema_down(sema_t* sema);
bool sys_sema_up(sema_t* sema);
tid_t get_tid(void);


void syscall_init(void) {
  lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame* f) {
  check_user_vaddr(f->esp, false);
  uint32_t args[4];
  args[0] = get_syscall_number(f);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  //printf("System call number: %d\n", args[0]);

  if (args[0] == SYS_EXIT) {
    get_args(f, args, 1);
    f->eax = args[1];
    Exit(args[1]);
  }

  else if (args[0] == SYS_PRACTICE) {
    get_args(f, args, 1);
    f->eax = args[1] + 1;
  }

  else if (args[0] == SYS_HALT) {
    shutdown_power_off();
  }

  else if (args[0] == SYS_EXEC) {
    get_args(f, args, 1);
    check_user_string((const char*)args[1]);
    f->eax = process_execute((const char*)args[1]);
  }

  else if (args[0] == SYS_WAIT) {
    get_args(f, args, 1);
    f->eax = process_wait((pid_t)args[1]);
  }

  else if (args[0] == SYS_FORK) {
    f->eax = fork(f);
  }

  else if (args[0] == SYS_CREATE) {
    get_args(f, args, 2);
    check_user_string((const char*)args[1]);
    f->eax = create((const char*)args[1], (unsigned)args[2]);
  }

  else if (args[0] == SYS_REMOVE) {
    get_args(f, args, 1);
    check_user_string((const char*)args[1]);
    f->eax = remove((const char*)args[1]);
  }

  else if (args[0] == SYS_OPEN) {
    get_args(f, args, 1);
    check_user_string((const char*)args[1]);
    f->eax = open((const char*)args[1]);
  }

  else if (args[0] == SYS_FILESIZE) {
    get_args(f, args, 1);
    f->eax = filesize(args[1]);
  }

  else if (args[0] == SYS_READ) {
    get_args(f, args, 3);
    check_user_buffer((const void*)args[2], (unsigned)args[3], true);
    f->eax = read(args[1], (void*)args[2], (unsigned)args[3]);
  }

  else if (args[0] == SYS_WRITE) {
    get_args(f, args, 3);
    check_user_buffer((const void*)args[2], (unsigned)args[3], false);
    f->eax = write(args[1], (const void*)args[2], (unsigned)args[3]);
  }

  else if (args[0] == SYS_SEEK) {
    get_args(f, args, 2);
    seek(args[1], (unsigned)args[2]);
  }

  else if (args[0] == SYS_TELL) {
    get_args(f, args, 1);
    f->eax = tell(args[1]);
  }

  else if (args[0] == SYS_CLOSE) {
    get_args(f, args, 1);
    close(args[1]);
  }

  else if (args[0] == SYS_PT_CREATE) {
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

  else if (args[0] == SYS_PT_EXIT) {
    sys_pthread_exit();
  }

  else if (args[0] == SYS_PT_JOIN) {
    get_args(f, args, 1);
    f->eax = sys_pthread_join((tid_t)args[1]);
  }

  else if (args[0] == SYS_LOCK_INIT) {
    get_args(f, args, 1);
    if (args[1] == 0) {
      /* User-level lock_init(NULL) should fail gracefully. */
      f->eax = false;
    } else {
      check_user_vaddr((void*)args[1], true);
      f->eax = sys_lock_init((lock_t*)args[1]);
    }
  }

  else if (args[0] == SYS_LOCK_ACQUIRE) {
    get_args(f, args, 1);
    check_user_vaddr((void*)args[1], true);
    f->eax = sys_lock_acquire((lock_t*)args[1]);
  }

  else if (args[0] == SYS_LOCK_RELEASE) {
    get_args(f, args, 1);
    check_user_vaddr((void*)args[1], true);
    f->eax = sys_lock_release((lock_t*)args[1]);
  }

  else if (args[0] == SYS_SEMA_INIT) {
    get_args(f, args, 2);
    if (args[1] == 0) {
      /* User-level sema_init(NULL, ...) should fail gracefully. */
      f->eax = false;
    } else {
      check_user_vaddr((void*)args[1], true);
      f->eax = sys_sema_init((sema_t*)args[1], (int)args[2]);
    }
  }

  else if (args[0] == SYS_SEMA_DOWN) {
    get_args(f, args, 1);
    check_user_vaddr((void*)args[1], true);
    f->eax = sys_sema_down((sema_t*)args[1]);
  }

  else if (args[0] == SYS_SEMA_UP) {
    get_args(f, args, 1);
    check_user_vaddr((void*)args[1], true);
    f->eax = sys_sema_up((sema_t*)args[1]);
  }

  else if (args[0] == SYS_GET_TID) {
    f->eax = get_tid();
  }

  else {
    Exit(-1); // Syscall number is not valid.
  }
}

/* Specific system call implementations. */

/* exit implementation. */
void Exit(int status) {
  struct thread* cur = thread_current();
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }
  struct child* cp = cur->pcb->child_process;
  if (cp != NULL) {
    cp->exit_status = status;
  }
  printf("%s: exit(%d)\n", cur->pcb->process_name, status);
  process_exit();
}

/* fork implementation helper struct and function. */
struct fork_helper {
  struct thread* parent;
  struct child* child_proc;
  struct intr_frame if_;
};

static void fork_process(void* addr) {
  struct fork_helper* helper = (struct fork_helper*)addr;
  struct thread* parent = helper->parent;
  struct child* child_proc = helper->child_proc;
  struct thread* child = thread_current();
  struct intr_frame* if_ = &helper->if_;
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
    list_init(&child->pcb->child_list);
    child->pcb->child_process = child_proc;
    child->pcb->next_fd = 2; // Start assigning fds from 2 (0 and 1 are stdin and stdout)
    list_init(&child->pcb->open_files);
    child->pcb->executable_file = NULL;
  }

  /* Copy parent's address space */
  if (success) {
    /* Allocate and activate page directory. */
    child->pcb->pagedir = pagedir_create();
    if (child->pcb->pagedir == NULL)
      goto done;
    cp_success = pagedir_copy(child->pcb->pagedir, parent->pcb->pagedir);
    if (!cp_success)
      goto done;
    process_activate();
  }

  /* Copy parent's file descriptors. */
  if (success) {
    lock_acquire(&filesys_lock);
    struct list_elem* e;
    for (e = list_begin(&parent->pcb->open_files); e != list_end(&parent->pcb->open_files);
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
      child_pf->fd = child->pcb->next_fd++;
      list_push_back(&child->pcb->open_files, &child_pf->elem);
    }
    lock_release(&filesys_lock);
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

pid_t fork(struct intr_frame* f) {
  struct thread* cur = thread_current();
  struct child* child_proc = child_init();
  if (child_proc == NULL)
    return -1;
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

/* File operation syscalls implementation. */

bool create(const char* file, unsigned initial_size) {
  lock_acquire(&filesys_lock);
  bool result;
  result = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return result;
}

bool remove(const char* file) {
  lock_acquire(&filesys_lock);
  bool result;
  result = filesys_remove(file);
  lock_release(&filesys_lock);
  return result;
}

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

void seek(int fd, unsigned position) {
  lock_acquire(&filesys_lock);
  struct file* f = process_get_file(fd);
  if (f != NULL) {
    file_seek(f, position);
  }
  lock_release(&filesys_lock);
}

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

void close(int fd) {
  lock_acquire(&filesys_lock);
  struct file* f = process_get_file(fd);
  if (f != NULL) {
    process_close_file(fd);
  }
  lock_release(&filesys_lock);
}

/* Multithreading syscalls. */

tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg) {
  return pthread_execute(sfun, tfun, arg);
}

void sys_pthread_exit(void) {
  pthread_exit();
}

tid_t sys_pthread_join(tid_t tid) {
  return pthread_join(tid);
}

tid_t get_tid(void) {
  return thread_current()->tid;
}

/* User-level synchronization syscalls. */

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

/* Functions working on checking validation and byte operations. */

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault occurred. */
static int get_user(const uint8_t* uaddr) {
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool put_user(uint8_t* udst, uint8_t byte) {
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:" : "=&a"(error_code), "=m"(*udst) : "q"(byte));
  return error_code != -1;
}

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

/* Checks if a user string is valid. If not, terminates the process. */
void check_user_string(const char* str) {
  const uint8_t* ptr = (const uint8_t*)str;
  check_user_vaddr((void*)ptr, false);
  while (ptr++) {
    int get = get_user(ptr);
    if (get == -1)
      Exit(-1); // invalid
    if (get == 0)
      break; // '/0'
  }
}

/* Checks if a user buffer for read and write is valid. */
void check_user_buffer(const void* buffer, unsigned size, bool write) {
  void* ptr = (void*)buffer;
  for (unsigned i = 0; i < size; i++) {
    check_user_vaddr(ptr + i, write);
  }
}

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

    /* Safely read 4 bytes for this argument from the user stack.
       Each byte must be a valid user address and readable. */
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
