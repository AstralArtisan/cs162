#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler(struct intr_frame*);
static int get_user(const uint8_t* uaddr);
static bool put_user(uint8_t* udst, uint8_t byte);
void check_user_vaddr(const void* vaddr, bool write);
void* user_to_kernel(void* uaddr);


void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  check_user_vaddr(f->esp, false);
  uint32_t* args = (uint32_t*)(f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  printf("System call number: %d\n", args[0]); 

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    exit(args[1]);
  }

  if (args[0] == SYS_PRACTICE) {
    f->eax = args[1] + 1;
  }

  if (args[0] == SYS_HALT) {
    shutdown_power_off();
  }

  if (args[0] == SYS_EXEC) {
    f->eax = process_execute((const char*)args[1]);
  }

  if (args[0] == SYS_WAIT) {
    f->eax = process_wait((pid_t)args[1]);
  }

  if (args[0] == SYS_FORK) {
    f->eax = -1;
  }
}

void exit(int status) {
  struct child* cp = thread_current()->child_process;
  if (cp != NULL) {
    cp->exit_status = status;
  }
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  process_exit();
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
  if (!is_user_vaddr(vaddr)) exit(-1);
  if (write) {
    if (!put_user((uint8_t*)vaddr, 0)) exit(-1);
  } else {
    if (get_user((const uint8_t*)vaddr) == -1) exit(-1);
  }
}

/* Converts a user virtual address to a kernel virtual address. */
void* user_to_kernel(void* uaddr) {
  void* kaddr = pagedir_get_page(thread_current()->pcb->pagedir,uaddr);
  if (kaddr == NULL) exit(-1);
  return kaddr;
}
