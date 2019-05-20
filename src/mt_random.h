#ifndef MT_RANDOM_H
#define MT_RANDOM_H
#include <stdint.h>

void rand_init_genrand(uint32_t s);
void rand_init_by_array();
uint32_t rand_genrand_int32(void);

#endif
