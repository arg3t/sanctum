#ifndef SANCTUM_PROTECTED_H
  #define SANCTUM_PROTECTED_H

  #include "linux/types.h"

  /*
     The sanctum datatype
     Stores details of each protected directory:
      - path:
      - owner:
  */
  typedef struct Sanctum {
    char* path;
    pid_t owner;

    // These fields are for the linked list
    bool sentinel;
    struct Sanctum* next;
    struct Sanctum* prev;
  } sanctum_t;


  /*
     This returns an empty sanctum linked list, with two
     sentinel nodes.

     free_sanctum must be called with the returned value
     in order to free the allocated memory in the entire
     linked list
  */
  sanctum_t *init_sanctum(void);

  sanctum_t add_sanctum(sanctum_t* ll, sanctum_t* new);

  sanctum_t remove_sanctum(sanctum_t* ll, char* path);

  sanctum_t free_sanctum(sanctum_t* ll, char* path);
#endif
