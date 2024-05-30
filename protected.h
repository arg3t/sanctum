#ifndef SANCTUM_PROTECTED_H
  #define SANCTUM_PROTECTED_H

  #include "linux/path.h"
#include "linux/types.h"
  #include "sanctum_init.h"

  #define ORIG_SYSCALL(nr) get_original_syscall(nr)(regs)


  /*
     The sanctum datatype
     Stores details of each protected directory:
      - path:
      - owner:
  */
  typedef struct Sanctum {
    struct path path;
    char key[SANCTUM_KEY_SIZE];
    size_t keylen;
    pid_t owner;

    // These fields are for the linked list
    bool sentinel;
    struct Sanctum* next;
    struct Sanctum* prev;
  } sanctum_t;

  void convert_to_readable(char* str, size_t n);

  /*
     This returns an empty sanctum linked list, with two
     sentinel nodes.

     free_sanctum must be called with the returned value
     in order to free the allocated memory in the entire
     linked list
  */
  sanctum_t *init_sanctum(struct path* path, pid_t owner);

  void print_sanctum(sanctum_t* sanctum);

  int8_t add_sanctum(sanctum_t* head, sanctum_t* new);

  sanctum_t* remove_sanctum(sanctum_t* head, struct path* path);

  sanctum_t* find_sanctum(sanctum_t* head, struct path* path);

  int8_t free_sanctum(sanctum_t* head);

  int8_t free_all_sanctums(sanctum_t* head);
#endif
