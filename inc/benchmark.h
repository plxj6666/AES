#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

#define NSPERS 1000000000

#ifdef __linux__

#elif defined(_WIN32) || defined(_WIN64)

#include <windows.h>

#else

#endif

   /*============================================================================*/
   /* Symmetric Cipher Bench                                                         */
   /*============================================================================*/

   /**
    * BITS_PER_SECOND
    * Runs a new benchmark.
    * bench the throughput of symmetric ciphers with (K/M/G)bps
    *
    * @param[in] LABEL			- the label for this benchmark.
    * @param[in] BENCHS         - Number of times each benchmark is ran.
    */
#define BPS_BENCH_START(_LABEL, _BENCHS)                 \
    {                                                    \
        uint64_t time_t[_BENCHS];                        \
        int benchs_ = _BENCHS;                       \
        int retrys;                                 \
        printf("BLOCK_CIPHER_THROUGHPUT: " _LABEL "\n"); \
        for (int _b = 0; _b < benchs_; _b++){


    /**
     * Measures the throughput of of FUNCTION.
     *
     * @param[in] FUNCTION		- the function executed.
     */
#define BPS_BENCH_ITEM(_FUNCTION, _ROUNDS)                  \
    retrys = _ROUNDS;                                  \
    _FUNCTION;                                              \
    time_bench_before();                                    \
    for (int _r = 0; _r < retrys; _r++) { _FUNCTION; } \
    time_bench_after(time_t, _b);


     /**
      * Prints the throughput of FUNCTION  with (K/M/G)bps
      * @param[in] DATASIZE             -bit length of data input to hash functions or block-size of block ciphers
      */
#define BPS_BENCH_FINAL(_DATASIZE)                               \
    }                                                            \
    print_sc_bps(time_t, benchs_, retrys, (_DATASIZE)); \
    }


      /*============================================================================*/
      /* Function definitions                                                       */
      /*============================================================================*/

#ifdef __cplusplus
extern "C" { /* start of __cplusplus */
#endif

    typedef struct timespec time_s;

    /**
     * Measures the time before a benchmark is executed.
     */
    void time_bench_before(void);

    /**
     * Measures the time after a benchmark.
     */
    void time_bench_after(uint64_t *t, int i);

    /**
     * Prints the last benchmark with bps.
     */
    void print_sc_bps(const uint64_t *t, int benches, int rounds, int block_size);

#ifdef __cplusplus
} /* end of __cplusplus */
#endif

#endif /* !BENCHMARK_H */
