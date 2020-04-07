/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <cstdint>

#include <random>
#include <algorithm>
#include <iostream>

constexpr uint32_t ARRAY_SIZE = 10*1024*1024;
constexpr uint32_t TEST_SIZE = 16;

inline uint64_t rdtsc()
{
    uint32_t tickl, tickh;
    __asm__ __volatile__("rdtsc":"=a"(tickl),"=d"(tickh));
    return ( static_cast<uint64_t>(tickh) << 32) | tickl;
}

void test_mem_write( uint64_t* big_array, const uint32_t* test_index_array )
{
    uint64_t tsc_begin = rdtsc();

    for( uint32_t i = 0; i < TEST_SIZE; ++i )
    {
        big_array[test_index_array[i]] = 0xAAFF77EE00101900;
    }
    uint64_t tsc_end = rdtsc();
    std::cout << "tsc\n" << tsc_begin << "\n" << tsc_end << "\n";
    std::cout << "test got " << tsc_end - tsc_begin << " clocks\n";
}

int main()
{
    auto big_array = new uint64_t[ARRAY_SIZE];
    std::fill( big_array, big_array+ARRAY_SIZE, 0 );

    auto test_index_array = new uint32_t[TEST_SIZE];

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<uint32_t> uni( 0, ARRAY_SIZE-1 );

    for( uint32_t i = 0; i < TEST_SIZE; ++i )
        test_index_array[i] = uni(rng);

    for( uint32_t i = 0; i < TEST_SIZE; ++i )
        std::cout << test_index_array[i] << " ";
    std::cout << "\n";

    test_mem_write( big_array, test_index_array );

    return 0;
}
