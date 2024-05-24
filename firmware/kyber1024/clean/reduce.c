#include "params.h"
#include "reduce.h"
#include <stdint.h>
//#define DISABLE_BENCH_MARKING_L4
#ifndef DISABLE_BENCH_MARKING_L4
#include <stdio.h>

static long L4_QINV_mult=0,L4_QINV_mult_count=0, L4_Aminust_Shift16=0, L4_Aminust_Shift16_count=0;
static long L4_mult_shift26_barrett_reduce=0,L4_mult_shift26_barrett_reduce_count=0;
void reset_global_benchmark_var_L4(void)
{
    L4_QINV_mult = 0;
    L4_QINV_mult_count = 0;
    L4_Aminust_Shift16 = 0;
    L4_Aminust_Shift16_count = 0;
    L4_mult_shift26_barrett_reduce=0;
    L4_mult_shift26_barrett_reduce_count=0;
}
void print_global_benchmark_var_montgomery_reduce(void)
{
    fprintf(stdout, "L4: L4_QINV_mult cycles = %ld, L4_QINV_mult_count:%ld, L4_Aminust_Shift16:%ld, L4_Aminust_Shift16_count:%ld\n", L4_QINV_mult,L4_QINV_mult_count,L4_Aminust_Shift16,L4_Aminust_Shift16_count);
}
void print_global_benchmark_var_barrett_reduce(void)
{
    fprintf(stdout, "L4: L4_mult_shift26_barrett_reduce:%ld, L4_mult_shift26_barrett_reduce_count:%ld\n", L4_mult_shift26_barrett_reduce,L4_mult_shift26_barrett_reduce_count);
}

#define time(cycles)\
{\
	__asm__ volatile ("rdcycle %0" : "=r"(cycles));\
}
#endif // DISABLE_BENCH_MARKING_L4

/*************************************************
* Name:        PQCLEAN_KYBER1024_CLEAN_montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q, where R=2^16
*
* Arguments:   - int32_t a: input integer to be reduced;
*                           has to be in {-q2^15,...,q2^15-1}
*
* Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
**************************************************/
int16_t PQCLEAN_KYBER1024_CLEAN_montgomery_reduce(int32_t a) {
    int16_t t;
 #ifndef DISABLE_BENCH_MARKING_L4
    long            Begin_Time,
                End_Time;
 #endif // DISABLE_BENCH_MARKING_L4
 #ifndef DISABLE_BENCH_MARKING_L4
    time (Begin_Time);
 #endif // DISABLE_BENCH_MARKING_L4
    t = (int16_t)a * QINV;
#ifndef DISABLE_BENCH_MARKING_L4
    time (End_Time);
    //fprintf(stdout, "L4:  (int16_t)a * QINV; cycles = %ld, begin:%ld, end:%ld\n", End_Time - Begin_Time,Begin_Time,End_Time);
    L4_QINV_mult += End_Time - Begin_Time;
    ++L4_QINV_mult_count;
#endif // DISABLE_BENCH_MARKING_L4
 #ifndef DISABLE_BENCH_MARKING_L4
    time (Begin_Time);
 #endif // DISABLE_BENCH_MARKING_L4
    //t = (a - (int32_t)t * KYBER_Q) >> 16;
    __asm__ volatile ("kyber %0, %1,%2\n" :"=r"(t):"r"(a),"r"((int32_t)t * KYBER_Q):);
#ifndef DISABLE_BENCH_MARKING_L4
    time (End_Time);
    //fprintf(stdout, "L4:  (a - (int32_t)t * KYBER_Q) >> 16; cycles = %ld, begin:%ld, end:%ld\n", End_Time - Begin_Time,Begin_Time,End_Time);
    L4_Aminust_Shift16 += End_Time - Begin_Time;
    ++L4_Aminust_Shift16_count;
#endif // DISABLE_BENCH_MARKING_L4
    return t;
}
/*************************************************
* Name:        PQCLEAN_KYBER1024_CLEAN_barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}
*
* Arguments:   - int16_t a: input integer to be reduced
*
* Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
**************************************************/
int16_t PQCLEAN_KYBER1024_CLEAN_barrett_reduce(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
 #ifndef DISABLE_BENCH_MARKING_L4
    long            Begin_Time,
                End_Time;
 #endif // DISABLE_BENCH_MARKING_L4

 #ifndef DISABLE_BENCH_MARKING_L4
    time (Begin_Time);
 #endif // DISABLE_BENCH_MARKING_L4

    t  = ((int32_t)v * a + (1 << 25)) >> 26;
#ifndef DISABLE_BENCH_MARKING_L4
    time (End_Time);
    L4_mult_shift26_barrett_reduce += End_Time - Begin_Time;
    ++L4_mult_shift26_barrett_reduce_count;
#endif // DISABLE_BENCH_MARKING_L4

    t *= KYBER_Q;

    return a - t;
}
