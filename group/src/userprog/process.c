#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp, int argc, char** argv);
bool setup_thread(void (**eip)(void), void** esp, stub_fun sf, pthread_fun tf, void* arg, int tnum);
struct lock filesys_lock;

static void init_pcb(struct process* pcb, struct thread* t) {
  pcb->pagedir = NULL;
  pcb->main_thread = t;
  strlcpy(pcb->process_name, t->name, sizeof pcb->process_name);
  list_init(&pcb->child_list);
  pcb->child_process = NULL;
  pcb->next_fd = 2; // Start assigning fds from 2 (0 and 1 are stdin and stdout)
  list_init(&pcb->open_files);
  pcb->executable_file = NULL;
  list_init(&pcb->locks);
  pcb->next_lock = 1;
  lock_init(&pcb->lock_protect);
  list_init(&pcb->semaphores);
  pcb->next_sema = 1;
  lock_init(&pcb->sema_protect);
  pcb->thread_count = 1;
  pcb->thread_bitmap = bitmap_create(MAX_THREADS);
  bitmap_set_all(pcb->thread_bitmap, false);
  lock_init(&pcb->thread_lock);
  list_init(&pcb->pt_list);
}
/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
  init_pcb(t->pcb, t);
}

/* Initializes a child process structure and adds it
   to the current thread's list of children. */
struct child* child_init() {
  struct child* child_proc = malloc(sizeof(struct child));
  struct process* p = thread_current()->pcb;
  if (child_proc == NULL || p == NULL)
    return NULL;
  child_proc->pid = TID_ERROR;
  child_proc->exit_status = -1;
  child_proc->waiting = false;
  child_proc->killed = false;
  child_proc->exited = false;
  child_proc->loaded = false;
  sema_init(&child_proc->wait_sema, 0);
  sema_init(&child_proc->load_sema, 0);
  list_push_back(&p->child_list, &child_proc->elem);
  return child_proc;
}

/* Searches the current thread's list of children
   for a child process with pid PID. Returns a pointer
   to the child process structure if found, NULL otherwise. */
struct child* find_child(pid_t pid) {
  struct process* p = thread_current()->pcb;
  struct list_elem* e;
  if (p == NULL)
    return NULL;
  for (e = list_begin(&p->child_list); e != list_end(&p->child_list); e = list_next(e)) {
    struct child* c = list_entry(e, struct child, elem);
    if (c->pid == pid)
      return c;
  }
  return NULL;
}

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
  if (fn_copy == NULL)
    return TID_ERROR;
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
  if (!child_proc->loaded)
    tid = TID_ERROR;
  if (tid == TID_ERROR) {
    list_remove(&child_proc->elem);
    free(child_proc);
  } else {
    child_proc->pid = tid;
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* file_name_) {
  struct exec_helper* helper = (struct exec_helper*)file_name_;
  char* file_name = helper->file_name;
  struct child* child_proc = helper->child_proc;
  free(helper);
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  /* Split the command line into arguments. */
  int argc = 0;
  char* argv[32];
  char* saveptr;
  char* token = strtok_r(file_name, " ", &saveptr);
  while (token != NULL) {
    argv[argc++] = token;
    token = strtok_r(NULL, " ", &saveptr);
  }

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    t->pcb = new_pcb;
    init_pcb(t->pcb, t);
    t->pcb->child_process = child_proc;
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(argv[0], &if_.eip, &if_.esp, argc, argv);
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  if (!success) {
    sema_up(&child_proc->load_sema);
    thread_exit();
  }
  child_proc->loaded = true;
  sema_up(&child_proc->load_sema);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting. */
int process_wait(pid_t child_pid) {
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

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;
  struct child* cp;
  struct list_elem* e;
  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  /* Free the current process's child processes. */
  if (!list_empty(&cur->pcb->child_list)) {
    for (e = list_begin(&cur->pcb->child_list); e != list_end(&cur->pcb->child_list);) {
      cp = list_entry(e, struct child, elem);
      struct list_elem* next = list_next(e);
      list_remove(&cp->elem);
      free(cp);
      e = next;
    }
  }

  if (cur->pcb->child_process) {
    cur->pcb->child_process->exited = true;
    sema_up(&cur->pcb->child_process->wait_sema);
  }

  /* Close all open files. */
  if (!list_empty(&cur->pcb->open_files)) {
    lock_acquire(&filesys_lock);
    struct list_elem* e;
    for (e = list_begin(&cur->pcb->open_files); e != list_end(&cur->pcb->open_files);) {
      struct pfile* pf = list_entry(e, struct pfile, elem);
      struct list_elem* next = list_next(e);
      file_close(pf->file);
      list_remove(&pf->elem);
      free(pf);
      e = next;
    }
    lock_release(&filesys_lock);
  }

  /* Free user-level locks owned by this process. */
  if (!list_empty(&cur->pcb->locks)) {
    lock_acquire(&cur->pcb->lock_protect);
    for (e = list_begin(&cur->pcb->locks); e != list_end(&cur->pcb->locks);) {
      struct lock_map* lm = list_entry(e, struct lock_map, elem);
      struct list_elem* next = list_next(e);
      list_remove(&lm->elem);
      free(lm->lock);
      free(lm);
      e = next;
    }
    lock_release(&cur->pcb->lock_protect);
  }

  /* Free user-level semaphores owned by this process. */
  if (!list_empty(&cur->pcb->semaphores)) {
    lock_acquire(&cur->pcb->sema_protect);
    for (e = list_begin(&cur->pcb->semaphores); e != list_end(&cur->pcb->semaphores);) {
      struct sema_map* sm = list_entry(e, struct sema_map, elem);
      struct list_elem* next = list_next(e);
      list_remove(&sm->elem);
      free(sm->sema);
      free(sm);
      e = next;
    }
    lock_release(&cur->pcb->sema_protect);
  }

  if (cur->pcb->thread_bitmap != NULL) {
    bitmap_destroy(cur->pcb->thread_bitmap);
    cur->pcb->thread_bitmap = NULL;
  }

  if (cur->pcb->executable_file != NULL) {
    file_allow_write(cur->pcb->executable_file);
    file_close(cur->pcb->executable_file);
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;
  free(pcb_to_free);
  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* Allocates a file descriptor to an open file.*/
int process_open_file(struct file* f) {
  struct process* p = thread_current()->pcb;
  struct pfile* pf = malloc(sizeof(struct pfile));
  if (p == NULL || pf == NULL)
    return -1;
  pf->file = f;
  pf->fd = p->next_fd++;
  list_push_back(&p->open_files, &pf->elem);
  return pf->fd;
}

/* Retrieves the file associated with a given file descriptor.*/
struct file* process_get_file(int fd) {
  struct process* p = thread_current()->pcb;
  struct list_elem* e;
  if (p == NULL)
    return NULL;
  for (e = list_begin(&p->open_files); e != list_end(&p->open_files); e = list_next(e)) {
    struct pfile* pf = list_entry(e, struct pfile, elem);
    if (pf->fd == fd) {
      return pf->file;
    }
  }
  return NULL;
}

/* Closes the file associated with a given file descriptor.*/
void process_close_file(int fd) {
  struct process* p = thread_current()->pcb;
  struct list_elem* e;
  if (p == NULL)
    return;
  for (e = list_begin(&p->open_files); e != list_end(&p->open_files); e = list_next(e)) {
    struct pfile* pf = list_entry(e, struct pfile, elem);
    if (pf->fd == fd) {
      file_close(pf->file);
      list_remove(&pf->elem);
      free(pf);
      return;
    }
  }
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp, int argc, char** argv);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp, int argc, char** argv) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  lock_acquire(&filesys_lock);
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }
  file_deny_write(file);
  t->pcb->executable_file = file;

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp, argc, argv))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  lock_release(&filesys_lock);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp, int argc, char** argv) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (!success) {
      palloc_free_page(kpage);
      return false;
    }

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
    size_t meta_size = sizeof(char*)          /* NULL sentinel for argv[argc] */
                       + argc * sizeof(char*) /* argv[i] pointers */
                       + sizeof(char**)       /* argv */
                       + sizeof(int)          /* argc */
                       + sizeof(void*);       /* fake return address */

    /* Extra words consumed on entry to user code. For main(argc, argv), 
       argc, argv, and main's return address will be pushed in. */
    const size_t kStartOverhead = 2 * sizeof(void*) + sizeof(void*); /* 12 bytes */

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
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }



/* User pthreads implementation. */
#define STACK_PAGES 1
#define STACK_SIZE (STACK_PAGES * PGSIZE)

/* Since bitmap begins after main thread, when we try to get the stack top,
   we need to skip it, by (tnum + 1) */
static void* stack_top(int tnum) { return (void*)(PHYS_BASE - (tnum + 1) * STACK_SIZE); }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.
   TNUM is like the id of user threads we are creating now.
  */
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
    if (kpage == NULL) {
      goto fail;
    }
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
  memset(kpage + (sp - bottom), 0, sizeof(void*));  // Push fake return address

  *esp = (void*)sp;
  return true;

fail:
  for (int i = 0; i < mapped; i++) {
    pagedir_clear_page(p->pagedir, upages[i]);
    palloc_free_page(kpages[i]);
  }
  return false;
}

/* Structure to hold arguments for start_pthread */
struct start_helper {
  stub_fun sf;
  pthread_fun tf;
  void* arg;
  struct pt* t;
  struct process* p;
  struct semaphore load_sema;
  bool loaded;
};

/* stack helpers */
/* If includes vm, this piece of code needs a big change. */

static int alloc_stack(struct process* p) {
  lock_acquire(&p->thread_lock);
  size_t idx = bitmap_scan_and_flip(p->thread_bitmap, 0, 1, false);
  lock_release(&p->thread_lock);
  if (idx == BITMAP_ERROR)
    return -1;
  return (int)idx;
}

static void free_stack(struct process* p, int tnum) {
  lock_acquire(&p->thread_lock);
  bitmap_set(p->thread_bitmap, tnum, false);
  lock_release(&p->thread_lock);
}

/* Unmaps and frees all user pages backing thread stack slot TNUM. */
static void free_stack_pages(struct process* p, int tnum) {
  if (p == NULL || p->pagedir == NULL)
    return;

  uint8_t* top = (uint8_t*)stack_top(tnum);
  for (int i = 0; i < STACK_PAGES; i++) {
    uint8_t* upage = top - (i + 1) * PGSIZE;
    uint8_t* kpage = pagedir_get_page(p->pagedir, upage);
    if (kpage != NULL) {
      pagedir_clear_page(p->pagedir, upage);
      palloc_free_page(kpage);
    }
  }
}

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

static struct pt* find_pthread(tid_t tid) {
  struct process* p = thread_current()->pcb;
  if (p == NULL)
    return NULL;
  struct list_elem* e;
  for (e = list_begin(&p->pt_list); e != list_end(&p->pt_list); e = list_next(e)) {
    struct pt* t = list_entry(e, struct pt, elem);
    if (t->tid == tid) {
      return t;
    }
  }
  return NULL;
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly. */
tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) { 
  tid_t tid;
  struct process* p = thread_current()->pcb;
  if (p == NULL) {
    return TID_ERROR;
  }
  struct pt* t = pt_init();
  if (t == NULL) {
    return TID_ERROR;
  }
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
  list_push_back(&p->pt_list, &exec_->t->elem);

  sema_down(&exec_->load_sema);
  if (!exec_->loaded) {
    list_remove(&exec_->t->elem);
    tid = TID_ERROR;
    free_stack(p, tnum);
    free(t);
  }
  free(exec_);
  return tid; 
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB. */
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

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting. */
tid_t pthread_join(tid_t tid) { 
  struct process* p = thread_current()->pcb;
  struct pt* t = find_pthread(tid);
  if (t == NULL || t->joined) {
    return TID_ERROR;
  }
  t->joined = true;
  if (!t->exited) {
    sema_down(&t->wait_sema); // Wait for thread to exit
  }
  free_stack_pages(p, t->tnum);
  list_remove(&t->elem);
  free_stack(p, t->tnum);
  free(t);
  return tid;
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below. */
void pthread_exit(void) {
  struct thread* cur = thread_current();
  struct process* p = cur->pcb;
  struct pt* t;
  if (p == NULL) {
    goto exit;
  }
  t = find_pthread(cur->tid);
  if (t == NULL) {
    goto exit;
  }
  t->exited = true;
  sema_up(&t->wait_sema);
exit:
  thread_exit();
  NOT_REACHED();
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit. */
void pthread_exit_main(void) {
  struct thread* cur = thread_current();
  struct process* p = cur->pcb;
  if (p == NULL) {
    return;
  }
  struct list_elem* e;
  for (e = list_begin(&p->pt_list); e != list_end(&p->pt_list); e = list_next(e)) {
    struct pt* t = list_entry(e, struct pt, elem);
    if (!t->joined) {
      pthread_join(t->tid);
    }
  }
  p->child_process->exit_status = 0;
  process_exit();
  NOT_REACHED();
}
