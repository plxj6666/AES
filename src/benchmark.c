#include "benchmark.h"

/*============================================================================*/
/* Time Bench                                                                 */
/*============================================================================*/

#ifdef __linux__

static struct
{
    /** Stores the time measured before the execution of the benchmark. */
    time_s before;
    /** Stores the time measured after the execution of the benchmark. */
    time_s after;
} g_bench;

/**
 * compute the time between start and end, using the time_s struct
 *
 * @param end       -the start of the execution
 * @param start     -the end of the execution
 * @return
 */
static time_s time_sub(time_s *end, time_s *start)
{
    time_s temp;
    if ((end->tv_nsec - start->tv_nsec) < 0)
    {
        temp.tv_sec = end->tv_sec - start->tv_sec - 1;
        temp.tv_nsec = NSPERS + end->tv_nsec - start->tv_nsec;
    }
    else
    {
        temp.tv_sec = end->tv_sec - start->tv_sec;
        temp.tv_nsec = end->tv_nsec - start->tv_nsec;
    }
    return temp;
}

void time_bench_before() { clock_gettime(CLOCK_MONOTONIC, &g_bench.before); }

void time_bench_after(uint64_t *t, int i)
{
    clock_gettime(CLOCK_MONOTONIC, &g_bench.after);
    time_s temp = time_sub(&g_bench.after, &g_bench.before);
    t[i] = temp.tv_sec * NSPERS + temp.tv_nsec;
}

#elif defined(_WIN32) || defined(_WIN64)

static struct
{
    /** Stores the time measured before the execution of the benchmark. */
    LARGE_INTEGER before;
    /** Stores the time measured after the execution of the benchmark. */
    LARGE_INTEGER after;
} g_bench;

void time_bench_before() { QueryPerformanceCounter(&g_bench.before); }

void time_bench_after(uint64_t *t, int i)
{
    QueryPerformanceCounter(&g_bench.after);
    LARGE_INTEGER Frequency;
    QueryPerformanceFrequency(&Frequency);
    int64_t temp = g_bench.after.QuadPart - g_bench.before.QuadPart;
    t[i] = (NSPERS * temp) / Frequency.QuadPart;
}

#else

#endif



/*============================================================================*/
/* Block Cipher Bench                                                         */
/*============================================================================*/

void print_sc_bps(const uint64_t *t, int benches, int rounds, int block_size)
{
    if (benches < 2)
    {
        fprintf(stderr, "ERROR: Need a least two bench counts!\n");
        return;
    }

    uint64_t acc = 0;

    for (int i = 0; i < benches; i++) acc += t[i];

    uint64_t bits = benches * rounds * block_size;

    double kbits = (double)bits / (1 << 10);

    double mbits = (double)bits / (1 << 20);

    double gbits = (double)bits / (1 << 30);

    double secend = (double)acc / NSPERS;

    double throughpt_bits_s = (double)bits / secend;// bits/s

    double throughpt_kbits_s = (double)kbits / secend;// kbits/s

    double throughpt_mbits_s = (double)mbits / secend;// mbits/s

    double throughpt_gbits_s = (double)gbits / secend;// gbits/s

    printf("Execute time: %f s\n", secend);
    if (throughpt_bits_s < 1000) printf("Throughpt: %f bps\n", throughpt_bits_s);
    else if (throughpt_kbits_s < 1000)
        printf("Throughpt: %f Kbps\n", throughpt_kbits_s);
    else if (throughpt_mbits_s < 1000)
        printf("Throughpt: %f Mbps\n", throughpt_mbits_s);
    else
        printf("Throughpt: %f Gbps\n", throughpt_gbits_s);

    printf("\n");
}

