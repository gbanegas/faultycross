#ifndef SEED_H
#define SEED_H

#include <stdint.h>

#define SEED_TREE_ADDR(h, i) ((1 << (h)) - 1 + (i))

void print_tree(uint8_t *stree);
void print_array(uint8_t *stree, int size);

void t_hash(uint8_t *stree, uint8_t *salt, int h, int i);

#define STREE_TO_PATH 0
#define PATH_TO_STREE 1

void stree_to_path_to_stree(uint8_t *stree, uint8_t *h, uint8_t *path, uint8_t *salt, int mode);
void stree_to_path_to_stree_faulted(uint8_t *stree, uint8_t *h, uint8_t *path, uint8_t *salt, int mode, int x);
uint16_t expected_path_length(uint8_t *h_digest);
uint16_t path_length(uint8_t *path);
uint8_t check_path(uint8_t *stree, uint8_t *path, uint8_t *h_digest, uint8_t * salt);
void flag_tree(uint8_t *ftree, uint8_t *h_digest);
uint8_t check_flag_tree(uint8_t *ftree, uint8_t *h_digest);
uint8_t ftree_to_path(uint8_t * path, uint8_t * ftree, uint8_t * stree);

#define stree_to_path(stree, h, path, salt) stree_to_path_to_stree(stree, h, path, salt, STREE_TO_PATH)
#define path_to_stree(stree, h, path, salt) stree_to_path_to_stree(stree, h, path, salt, PATH_TO_STREE)

#define stree_to_path_faulted(stree, h, path, salt,x) stree_to_path_to_stree_faulted(stree, h, path, salt, STREE_TO_PATH,x)
#define path_to_stree_faulted(stree, h, path, salt,x) stree_to_path_to_stree_faulted(stree, h, path, salt, PATH_TO_STREE,x)


#endif

