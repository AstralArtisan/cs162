#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>
#include <bitmap.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;
typedef char lock_t;
typedef char sema_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

struct child;
struct file;

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  
  struct list child_list;       /* List of child processes */
  struct child* child_process;  /* Pointer to child process struct */
  int next_fd;                  /* Next file descriptor to be assigned */
  struct list open_files;       /* List of open files */
  struct file* executable_file; /* File the thread is executing */
  
  struct list locks;          /* Locks held by the process */
  lock_t next_lock;         /* Next lock identifier */
  struct lock lock_protect;
  struct list semaphores;     /* Semaphores owned by the process */
  sema_t next_sema;          /* Next semaphore identifier */
  struct lock sema_protect;
  
  uint8_t thread_count;      /* Number of threads in the process */
  struct bitmap* thread_bitmap; /* Bitmap to track threads */
  struct lock thread_lock;   /* Lock to protect thread count */
  struct list pt_list;       /* List of join threads in the process */
  
  struct list_elem elem;
};

/* Stores the status of a child process. */
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

/* Tracks open files for a process. */
struct pfile {
  struct file* file;
  int fd; // file descriptor
  struct list_elem elem;
};

/* Stores the status of a pthread. */
struct pt {
  tid_t tid;
  bool exited;
  bool joined;
  int tnum;
  struct semaphore wait_sema;
  struct list_elem elem;
};

/* Maps locks to their identifiers for a process. */
struct lock_map {
  lock_t id;
  struct lock* lock;
  struct list_elem elem;
};

/* Maps semaphores to their identifiers for a process. */
struct sema_map {
  sema_t id;
  struct semaphore* sema;
  struct list_elem elem;
};

void userprog_init(void);

struct child* child_init(void);
struct child* find_child(pid_t);

pid_t process_execute(const char*);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);
int process_open_file(struct file*);
struct file* process_get_file(int);
void process_close_file(int);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
