#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define MAX_ARGS 3
#define STD_INPUT 0
#define STD_OUTPUT 1

//decleration
int getpage_ptr (const void *vaddr);
void remove_all_child_processes (void);
struct child_process* find_child_process (int pid);
void remove_child_process (struct child_process *child);
struct file* get_file(int filedes);
int add_file (struct file *file_name);
void syscall_halt (void);
bool create(const char* file_name, unsigned starting_size);
bool syscall_remove(const char* file_name);
int syscall_open(const char * file_name);
int syscall_filesize(int filedes);
int syscall_read(int filedes, void *buffer, unsigned length);
int syscall_write (int filedes, const void * buffer, unsigned byte_size);
void syscall_seek (int filedes, unsigned new_position);
unsigned syscall_tell(int fildes);
void syscall_close(int filedes);
void validate_ptr (const void* vaddr);
void validate_str (const void* str);
void validate_buffer (const void* buf, unsigned byte_size);
pid_t exec(const char* cmdline);
int wait(pid_t pid);
void exit (int status);
void process_close_file (int file_descriptor);
static void syscall_handler (struct intr_frame *);
void stack_access (struct intr_frame *f, int *arg, int num_of_args);
bool FILE_LOCK_INIT = false;

/*
 * System call initializer
 * It handles the set up for system call operations.
 */
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*
 * This method handles for various case of system command.
 * This handler invokes the proper function call to be carried
 * out base on the command line.
 */
static void
syscall_handler (struct intr_frame *f UNUSED) {

  if (!FILE_LOCK_INIT)
  {
    lock_init(&file_system_lock);
    FILE_LOCK_INIT = true;
  }
  
  int arg[MAX_ARGS];
  int esp = getpage_ptr((const void *) f->esp);
  
  switch (* (int *) esp)
  {
    /* Halt the operating system. */
    case SYS_HALT:
      shutdown_power_off();
      break;


    /* Terminate this process. */  
    case SYS_EXIT:

      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);

      //exit the process
      exit(arg[0]);

      break;


    /* Start another process. */  
    case SYS_EXEC: 
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);
      
      // check validity
      validate_str((const void *) arg[0]);
      
      // get page pointer (command line)
      arg[0] = getpage_ptr((const void *)arg[0]);

      // execute the command line
      f->eax = exec((const char *) arg[0]); 

      break;


    /* Wait for a child process to die. */  
    case SYS_WAIT:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);

      // execute
      f->eax = wait(arg[0]);
    
      break;



    /* Create a file. */  
    case SYS_CREATE:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 2);
      
      // check validity
      validate_str((const void *)arg[0]);
      
      // get page pointer
      arg[0] = getpage_ptr((const void *) arg[0]);
      
      // create this file
      f->eax = create((const char *)arg[0], (unsigned)arg[1]);  
    
      break;



    /* Delete a file. */  
    case SYS_REMOVE:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);
      
      // check validity 
      validate_str((const void*)arg[0]);
      
      // get page pointer
      arg[0] = getpage_ptr((const void *) arg[0]);
      
      // remove this file
      f->eax = syscall_remove((const char *)arg[0]);  
    
      break;



    /* Open a file. */  
    case SYS_OPEN:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);
      
      // check validity  
      validate_str((const void*)arg[0]);
     
     // get page pointer
      arg[0] = getpage_ptr((const void *)arg[0]);
      
      // open this file
      f->eax = syscall_open((const char *)arg[0]);  
    
      break;



    /* Obtain a file's size. */  
    case SYS_FILESIZE:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);
    
      // obtain file size
      f->eax = syscall_filesize(arg[0]);  
    
      break;



    /* Read from a file. */  
    case SYS_READ:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 3);
      
      // check validity 
      validate_buffer((const void*)arg[1], (unsigned)arg[2]);
       
      // get page pointer
      arg[1] = getpage_ptr((const void *)arg[1]); 
      
      //read file
      f->eax = syscall_read(arg[0], (void *) arg[1], (unsigned) arg[2]);
    
      break;



    /* Write to a file. */  
    case SYS_WRITE:
      
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 3);
      
      // check validity 
      validate_buffer((const void*)arg[1], (unsigned)arg[2]);

      // get page pointer
      arg[1] = getpage_ptr((const void *)arg[1]); 

      //write to the file
      f->eax = syscall_write(arg[0], (const void *) arg[1], (unsigned) arg[2]);

      break;



    /* Change position in a file. */  
    case SYS_SEEK:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 2);


      //change position
      syscall_seek(arg[0], (unsigned)arg[1]);
    
      break;



    /* Report current position in a file. */  
    case SYS_TELL:
    
      // take all the arguments needed to the arg from stack
      stack_access(f, &arg[0], 1);


      //get current position in file
      f->eax = syscall_tell(arg[0]);
    
      break;
    


    /* Close a file. */
    case SYS_CLOSE:
    
      // take all the arguments needed to the arg from stack
      stack_access (f, &arg[0], 1);

      //close file
      syscall_close(arg[0]);
    
      break;
      
    default:
      break;
  }
}


/* get arguments from stack */
void
stack_access (struct intr_frame *f, int *args, int num_of_args)
{
  int i;
  int *ptr;
  for (i = 0; i < num_of_args; i++)
  {
    ptr = (int *) f->esp + i + 1;
    validate_ptr((const void *) ptr);
    args[i] = *ptr;
  }
}


void
exit (int status)
{
  struct thread *cur = thread_current();
  
  if (check_thread_active(cur->parent) && cur->child_pr){
    if (status < 0)
      status = -1;
    cur->child_pr->status = status;
  }

  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}



int
wait(pid_t pid)
{
  return process_wait(pid);
}


bool
create(const char* file_name, unsigned starting_size)
{
  lock_acquire(&file_system_lock);
  bool success = filesys_create(file_name, starting_size);
  lock_release(&file_system_lock);
  return success;
}


bool
syscall_remove(const char* file_name)
{
  lock_acquire(&file_system_lock);
  bool success = filesys_remove(file_name);
  lock_release(&file_system_lock);
  return success;
}


int
syscall_open(const char *file_name)
{
  lock_acquire(&file_system_lock);
  struct file *file_ptr = filesys_open(file_name);
  if (!file_ptr)
  {
    lock_release(&file_system_lock);
    return SYS_ERROR;
  }
  int file_des = add_file(file_ptr);
  lock_release(&file_system_lock);
  return file_des;
}


void
syscall_close(int filedes)
{
  lock_acquire(&file_system_lock);
  process_close_file(filedes);
  lock_release(&file_system_lock);
}

int
syscall_read(int filedes, void *buffer, unsigned length)
{
  if (length <= 0)
  {
    return length;
  }
  
  if (filedes == STD_INPUT)
  {
    unsigned i = 0;
    uint8_t *local_buf = (uint8_t *) buffer;
    for (;i < length; i++)
    {
      // retrieve pressed key from the input buffer
      local_buf[i] = input_getc(); 
    }
    return length;
  }
  
  /* read from file */
  lock_acquire(&file_system_lock);
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    lock_release(&file_system_lock);
    return SYS_ERROR;
  }
  int bytes_read = file_read(file_ptr, buffer, length); // from file.h
  lock_release (&file_system_lock);
  return bytes_read;
}


int 
syscall_write (int filedes, const void * buffer, unsigned byte_size)
{
    if (byte_size <= 0)
    {
      return byte_size;
    }
    if (filedes == STD_OUTPUT)
    {
      putbuf (buffer, byte_size);
      return byte_size;
    }
    
    // start writing to file
    lock_acquire(&file_system_lock);
    struct file *file_ptr = get_file(filedes);
    if (!file_ptr)
    {
      lock_release(&file_system_lock);
      return SYS_ERROR;
    }
    int bytes_written = file_write(file_ptr, buffer, byte_size); 
    lock_release (&file_system_lock);
    return bytes_written;
}



pid_t
exec(const char* cmdline) //failed
{
    pid_t pid = process_execute(cmdline);
    struct child_process *child_process_ptr = find_child_process(pid);
    if (!child_process_ptr)
    {
      return SYS_ERROR;
    }
    /* check if process if loaded */
    if (child_process_ptr->load_status == NOT_LOADED)
    {
      sema_down(&child_process_ptr->load_sema);
    }
    /* check if process failed to load */
    if (child_process_ptr->load_status == LOAD_FAIL)
    {
      remove_child_process(child_process_ptr);
      return SYS_ERROR;
    }
    return pid;
}



int
syscall_filesize(int filedes)
{
  lock_acquire(&file_system_lock);
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    lock_release(&file_system_lock);
    return SYS_ERROR;
  }
  int filesize = file_length(file_ptr); // from file.h
  lock_release(&file_system_lock);
  return filesize;
}


void
syscall_seek (int filedes, unsigned new_position)
{
  lock_acquire(&file_system_lock);
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    lock_release(&file_system_lock);
    return;
  }
  file_seek(file_ptr, new_position);
  lock_release(&file_system_lock);
}


unsigned
syscall_tell(int filedes)
{
  lock_acquire(&file_system_lock);
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    lock_release(&file_system_lock);
    return SYS_ERROR;
  }
  off_t offset = file_tell(file_ptr);
  lock_release(&file_system_lock);
  return offset;
}


void
validate_ptr (const void *vaddr)
{
    if (vaddr < USER_VADDR_BOTTOM || !is_user_vaddr(vaddr))
      exit(SYS_ERROR);
    
}


void
validate_str (const void* str)
{
    for (; * (char *) getpage_ptr(str) != 0; str = (char *) str + 1);
}


void
validate_buffer(const void* buf, unsigned byte_size)
{
  unsigned i = 0;
  char* local_buffer = (char *)buf;
  for (; i < byte_size; i++)
  {
    validate_ptr((const void*)local_buffer);
    local_buffer++;
  }
}

/* get the pointer to page */
int
getpage_ptr(const void *vaddr)
{
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr)
    exit(SYS_ERROR);
  return (int)ptr;
}

/* find a child process based on pid */
struct child_process* find_child_process(int pid)
{
  struct thread *t = thread_current();
  struct list_elem *e;
  struct list_elem *next;
  
  for (e = list_begin(&t->child_list); e != list_end(&t->child_list); e = next)
  {
    next = list_next(e);
    struct child_process *child_pr = list_entry(e, struct child_process, elem);
    if (pid == child_pr->pid)
    {
      return child_pr;
    }
  }
  return NULL;
}

/* remove a specific child process */
void
remove_child_process (struct child_process *child_pr)
{
  list_remove(&child_pr->elem);
  free(child_pr);
}

/* remove all child processes for a thread */
void remove_all_child_processes (void) 
{
  struct thread *t = thread_current();
  struct list_elem *next;
  struct list_elem *e = list_begin(&t->child_list);
  
  for (;e != list_end(&t->child_list); e = next)
  {
    next = list_next(e);
    struct child_process *child_pr = list_entry(e, struct child_process, elem);
    list_remove(&child_pr->elem); //remove child process
    free(child_pr);
  }
}

/* add file to file list and return file descriptor of added file*/
int
add_file (struct file *file_name)
{
  struct process_file *process_file_ptr = malloc(sizeof(struct process_file));
  if (!process_file_ptr)
  {
    return SYS_ERROR;
  }
  process_file_ptr->file = file_name;
  process_file_ptr->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back(&thread_current()->file_list, &process_file_ptr->elem);
  return process_file_ptr->fd;
  
}

/* get file that matches file descriptor */
struct file*
get_file (int filedes)
{
  struct thread *t = thread_current();
  struct list_elem* next;
  struct list_elem* e = list_begin(&t->file_list);
  
  for (; e != list_end(&t->file_list); e = next)
  {
    next = list_next(e);
    struct process_file *process_file_ptr = list_entry(e, struct process_file, elem);
    if (filedes == process_file_ptr->fd)
    {
      return process_file_ptr->file;
    }
  }
  return NULL; // nothing found
}


/* close the desired file descriptor */
void
process_close_file (int file_descriptor)
{
  struct thread *t = thread_current();
  struct list_elem *next;
  struct list_elem *e = list_begin(&t->file_list);
  
  for (;e != list_end(&t->file_list); e = next)
  {
    next = list_next(e);
    struct process_file *process_file_ptr = list_entry (e, struct process_file, elem);
    if (file_descriptor == process_file_ptr->fd || file_descriptor == CLOSE_ALL_FD)
    {
      file_close(process_file_ptr->file);
      list_remove(&process_file_ptr->elem);
      free(process_file_ptr);
      if (file_descriptor != CLOSE_ALL_FD)
      {
        return;
      }
    }
  }
}

/**
 *
 * FAIL tests/userprog/sc-boundary-3
 * FAIL tests/userprog/exec-bound-2
 * FAIL tests/userprog/multi-recurse
 * rox 
 * bad
 * FAIL tests/userprog/no-vm/multi-oom
 * FAIL tests/filesys/base/syn-read
 **/
