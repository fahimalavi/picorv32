#ifndef PQCLEAN_KYBER1024_CLEAN_REDUCE_H
#define PQCLEAN_KYBER1024_CLEAN_REDUCE_H
#include "params.h"
#include <stdint.h>

#define MONT (-1044) // 2^16 mod q
#define QINV (-3327) // q^-1 mod 2^16

int16_t PQCLEAN_KYBER1024_CLEAN_montgomery_reduce(int32_t a);

int16_t PQCLEAN_KYBER1024_CLEAN_barrett_reduce(int16_t a);

#ifndef DISABLE_BENCH_MARKING_L4
void reset_global_benchmark_var_L4(void);
void print_global_benchmark_var_montgomery_reduce(void);
void print_global_benchmark_var_barrett_reduce(void);
#endif // DISABLE_BENCH_MARKING_L4

#endif
