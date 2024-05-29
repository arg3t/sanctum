#include "errors.h"
#include "linux/gfp_types.h"
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include "hooker.h"
#include "linux/printk.h"
#include "linux/random.h"
#include "linux/slab.h"
#include "protected.h"
#include "linux/stddef.h"
#include "sanctum_init.h"

void convert_to_readable(char* str, size_t n) {
  for (int i = 0; i < n - 1; i++){
    while(str[i] < 0x21 || str[i] > 0x7E){
      str[i] = get_random_u8();
    }
  }
  str[n-1] = 0;
}

sanctum_t *init_sanctum(char* path, pid_t owner) {
  sanctum_t* sanctum;

  // If path is null, create sentinel node
  if (path == NULL) {
    sanctum = kzalloc(sizeof(sanctum_t), GFP_KERNEL);
    memset(sanctum, 0, sizeof(sanctum_t));

    sanctum->sentinel = true;
    sanctum->next = sanctum;

    return sanctum;
  }

  if (strlen(path) >= MAX_PATH_LENGTH)
    return 0;

  sanctum = kzalloc(sizeof(sanctum_t), GFP_KERNEL);
  sanctum->pathlen = strlen(path);

  get_random_bytes_wait(sanctum->key, SANCTUM_KEY_SIZE);
  convert_to_readable(sanctum->key, SANCTUM_KEY_SIZE);

  sanctum->owner = owner;
  strncpy(sanctum->path, path, MAX_PATH_LENGTH);

  sanctum->name = sanctum->path + sanctum->pathlen;

  // Walk backwards on path until fw slash is found
  while (*sanctum->name != '/' && sanctum->name != sanctum->path) {
    sanctum->name--;
  }

  sanctum->name++;

  return sanctum;
}


int8_t add_sanctum(sanctum_t* head, sanctum_t* new) {
  sanctum_t* node = head;

  while(node->next != head){
    if (strcmp(node->next->path, new->path) == 0)
      return SEXIST;

    node = node->next;
  }

  node->next = new;
  new->next = head;

  return 0;
}


sanctum_t* remove_sanctum(sanctum_t* head, char* path) {
  sanctum_t* prev = head;
  sanctum_t* node = head->next;

  while(node != head){
    if (strcmp(node->path, path) == 0){
      prev->next = node->next;
      return node;
    }

    prev = node;
    node = node->next;
  }

  return 0;
}


int8_t free_sanctum(sanctum_t* sanctum) {
  kfree(sanctum);
  return 0;
}


int8_t free_all_sanctums(sanctum_t* head) {
  sanctum_t* foo;
  sanctum_t* node = head;

  do {
    foo = node;
    node = node->next;
    free_sanctum(foo);
  } while(node != head);

  return 0;
}


sanctum_t* find_sanctum(sanctum_t* head, char* path){
  sanctum_t* node = head;

  while(node->next != head){
    if (strncmp(node->next->path, path, node->next->pathlen) == 0)
      return node;

    node = node -> next;
  }

  return 0;
}


void print_sanctum(sanctum_t* head) {
  sanctum_t* node = head->next;
  int i = 0;

  while(node != head){
    printk("{\n\tidx: %d\n\tPath: %s\n\tKey: %s\n\tName: %s\n\tOwner: %d\n}\n", i, node->path, node->key, node->name, node->owner);
    node = node->next;
    i++;
  }
}
