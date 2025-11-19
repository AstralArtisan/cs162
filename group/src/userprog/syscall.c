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

static void syscall_handler(struct intr_frame*);
static int get_user(const uint8_t* uaddr);
static bool put_user(uint8_t* udst, uint8_t byte);
void check_user_vaddr(const void* vaddr, bool write);
void check_user_string(const char* str);
uint32_t get_syscall_number(struct intr_frame* f);
void get_args(struct intr_frame* f, uint32_t* args, int num);
void Exit(int status);
static void fork_process(void* addr);
pid_t fork(struct intr_frame* f);
void write(struct intr_frame *f, uint32_t* args);
void read(struct intr_frame *f, uint32_t* args);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
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

  else if (args[0] == SYS_READ) {
    read(f, args);
  }

  else if (args[0] == SYS_WRITE) {
    write(f, args);
  }

  else {
    Exit(-1); // Syscall number is not valid.
  }
}

void Exit(int status) {
  struct child* cp = thread_current()->child_process;
  if (cp != NULL) {
    cp->exit_status = status;
  }
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  process_exit();
}

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

void write(struct intr_frame *f, uint32_t* args) {
  get_args(f, args, 3);  
  int fd = args[1];     
  const char *buffer = (const char *)args[2]; 
  unsigned size = args[3]; 

  if (fd == 1) {
    putbuf(buffer, size);
    f->eax = size;       
  } else {
    f->eax = -1;       
  }
}

void read(struct intr_frame *f, uint32_t* args) {
  get_args(f, args, 3);
  int fd = args[1];
  uint8_t* buffer = (uint8_t*)args[2];
  unsigned size = args[3];

  if (fd == 0) {
    unsigned i;
    for (i = 0; i < size; i++) {
      check_user_vaddr(buffer + i, true);
      if (!put_user(buffer + i, input_getc())) {
        Exit(-1);
      }
    }
    f->eax = size;
  } else {
    f->eax = -1;
  }
}


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
