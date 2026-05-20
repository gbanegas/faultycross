#include <stdio.h>
#include <string.h>

#include "fips202.h"

#ifndef MEDS_t
#include "params.h"
#endif

#include "seed.h"
#include "log.h"

void print_tree(uint8_t *stree)
{
  int h = 0;
  int i = 0;

  int start = i;
  int end = i+1;

  for (; h < MEDS_seed_tree_height + 1; h++)
  {
    for (int i = 0; i < (1 << (MEDS_seed_tree_height - h))-1; i++)
      printf("  ");

    for (int i = start; i < end; i++)
    {
      if ((i << (MEDS_seed_tree_height - h)) >= MEDS_t)
        break;

      printf("%02x", stree[MEDS_st_seed_bytes * SEED_TREE_ADDR(h, i)]);

      for (int j = 0; j < ((1 << (MEDS_seed_tree_height - h)) - 1)*2 + 1; j++)
        printf("  ");
    }

    printf("\n");

    start = start<<1;
    end = end<<1;
  }
}

uint16_t expected_path_length(uint8_t *h_digest){

  uint16_t res = 0;
  uint8_t temp[MEDS_t];
  
  for (int i = 0; i < MEDS_t; i++){
    temp[i] = (h_digest[i] > 0);
  }
  
  for (int i = MEDS_seed_tree_height - 1; i>=0; i--){

    uint16_t lvlw = 1 << i; 

    for (int j = 0; j < lvlw; j++){
      uint8_t r = temp[2*j] + temp[2*j+1];
      if (r == 0){
        temp[j] = 0;
      } else {
        temp[j] = 1;
        if (r==1){
          res += 1;
        }
      }

    }

  }
  return res;

}

uint16_t path_length(uint8_t *path){

  uint8_t null_array[MEDS_st_seed_bytes] = {0};

  for (int i = 0; i < MEDS_t; i++){
    if (memcmp(null_array, path+i*MEDS_st_seed_bytes, MEDS_st_seed_bytes) == 0) {
      return i;
    }
  }

  return MEDS_t;

}

uint8_t check_path(uint8_t *stree, uint8_t *path, uint8_t *h_digest, uint8_t * salt){
  uint8_t rtree [MEDS_st_seed_bytes*SEED_TREE_size];
  stree_to_path_to_stree(rtree, h_digest, path, salt, PATH_TO_STREE);
  uint8_t null_array[MEDS_st_seed_bytes] = {0};

  for (int i = 0; i<MEDS_t; i++){
    if (h_digest[i] == 0){
      if (memcmp(rtree+(i*MEDS_st_seed_bytes), stree+(i*MEDS_st_seed_bytes), MEDS_st_seed_bytes) != 0) return 1;
    } else {
      if (memcmp(rtree+(i*MEDS_st_seed_bytes), null_array, MEDS_st_seed_bytes) != 0) return 1;
    }
  }
  return 0;
}

void print_array(uint8_t *stree, int size)
{
  printf("[ ");
  for (int i = 0; i < size; i++){
      
      printf("%02x", stree[MEDS_st_seed_bytes * i]);
      printf(", ");
  }
  printf("]\n");
}

void t_hash(uint8_t *stree, uint8_t *salt, int h, int i)
{
  keccak_state shake;

  int start = i;
  int end = i+1;

  uint8_t buf[MEDS_st_salt_bytes + MEDS_st_seed_bytes + sizeof(uint32_t)] = {0};

  memcpy(buf, salt, MEDS_st_salt_bytes);

  uint8_t *pos = buf + MEDS_st_salt_bytes + MEDS_st_seed_bytes;

  for (h = h+1; h < MEDS_seed_tree_height+1; h++)
  {
    start = start<<1;
    end = end<<1;

    if ((start << (MEDS_seed_tree_height - h)) >= MEDS_t)
      break;

    for (int i = start; i < end; i+=2)
    {
      if ((i << (MEDS_seed_tree_height - h)) >= MEDS_t)
        break;

      for (int j = 0; j < 4; j++)
        pos[j] = (SEED_TREE_ADDR(h-1, i>>1) >> (j*8)) & 0xff;

      memcpy(buf + MEDS_st_salt_bytes,
          &stree[MEDS_st_seed_bytes * SEED_TREE_ADDR(h-1, i>>1)],
          MEDS_st_seed_bytes);

      shake256_init(&shake);
      shake256_absorb(&shake, buf, MEDS_st_salt_bytes + MEDS_st_seed_bytes + sizeof(uint32_t));
      shake256_finalize(&shake);

      int len = 2*MEDS_st_seed_bytes;

      if (((i+1) << (MEDS_seed_tree_height - h)) >= MEDS_t)
        len = MEDS_st_seed_bytes;

      shake256_squeeze(&stree[MEDS_st_seed_bytes * SEED_TREE_ADDR(h, i)], len, &shake);
    }
  }
}

void stree_to_path_to_stree(uint8_t *stree, uint8_t *h_digest, uint8_t *path, uint8_t *salt, int mode)
{
  int h = 0;
  int i = 0;

  unsigned int id = 0;

  int idx = 0;

  unsigned int indices[MEDS_w] = {0};

  for (int i = 0; i < MEDS_t; i++)
    if (h_digest[i] > 0){
      indices[idx++] = i;
    }

  while (1 == 1)
  {
    int index_leaf = 0;

    // While we are on the right path to the current unpublished leaf
    while ((indices[id] >> (MEDS_seed_tree_height - h)) == i)
    {
      // Go down the tree
      h += 1;
      i <<= 1;

      // if we have reached the leaf level
      if (h > MEDS_seed_tree_height)
      {
        h -= 1;
        i >>= 1;

        if (id+1 < MEDS_w)
          id++;

        // do not publish this node
        // skip this ?
        index_leaf = 1;

        break;
      }
    }

    // The leaf should be published
    if (index_leaf == 0)
    {
      // if we are creating a path, add it to the path
      if (mode == STREE_TO_PATH)
      {
        memcpy(path, &stree[MEDS_st_seed_bytes * SEED_TREE_ADDR(h, i)], MEDS_st_seed_bytes);
        path += MEDS_st_seed_bytes;
      }
      else // if we are rebuilding the tree, fill the current node with the current seed in the path
      // fill the sub tree 
      {
        memcpy(&stree[MEDS_st_seed_bytes * SEED_TREE_ADDR(h, i)], path, MEDS_st_seed_bytes);
        path += MEDS_st_seed_bytes;

        t_hash(stree, salt, h, i);
      }
    }

    // backtrack
    while ((i & 1) == 1)
    {
      h -= 1;
      i >>= 1;
    }

    // next leaf
    i+=1;

    if ((i << (MEDS_seed_tree_height - h)) >= MEDS_t)
      return;
  }
}

void stree_to_path_to_stree_faulted(uint8_t *stree, uint8_t *h_digest, uint8_t *path, uint8_t *salt, int mode, int x)
{
  int h = 0;
  int i = 0;

  unsigned int id = 0;

  int idx = 0;

  unsigned int indices[MEDS_w] = {0};

  for (int i = 0; i < MEDS_t; i++)
    if (h_digest[i] > 0){
      indices[idx++] = i;
    }


  while (1 == 1)
  {
    int index_leaf = 0;

    // While we are on the right path to the current unpublished leaf
    while ((indices[id] >> (MEDS_seed_tree_height - h)) == i)
    {
      // Go down the tree
      h += 1;
      i <<= 1;

      // if we have reached the leaf level
      if (h > MEDS_seed_tree_height)
      {
        h -= 1;
        i >>= 1;

        if (id+1 < MEDS_w)
          id++;

        // do not publish this node
        // skip this ?
        if (x>=0 && indices[id-1] != x) index_leaf = 1;

        break;
      }
    }

    // The leaf should be published
    if (index_leaf == 0)
    {
      // if we are creating a path, add it to the path
      if (mode == STREE_TO_PATH)
      {
        memcpy(path, &stree[MEDS_st_seed_bytes * SEED_TREE_ADDR(h, i)], MEDS_st_seed_bytes);
        path += MEDS_st_seed_bytes;
      }
      else // if we are rebuilding the tree, fill the current node with the current seed in the path
      // fill the sub tree 
      {
        memcpy(&stree[MEDS_st_seed_bytes * SEED_TREE_ADDR(h, i)], path, MEDS_st_seed_bytes);
        path += MEDS_st_seed_bytes;

        t_hash(stree, salt, h, i);
      }
    }

    // backtrack
    while ((i & 1) == 1)
    {
      h -= 1;
      i >>= 1;
    }

    // next leaf
    i+=1;

    if ((i << (MEDS_seed_tree_height - h)) >= MEDS_t)
      return;
  }
}
