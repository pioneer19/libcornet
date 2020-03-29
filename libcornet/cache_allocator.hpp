/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 *
 * This file is part of libcornet.
 *
 *  libcornet is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libcornet is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with libcornet.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <cstdint>
#include <cstdlib>

#include <atomic>
#include <utility>
#include <cassert>

namespace pioneer19
{

template<size_t BUFFER_SIZE = 20 * 1024>
class alignas(64) CacheAllocator // cache line size alignment
{
public:
    CacheAllocator() = default;
    ~CacheAllocator() noexcept;

    CacheAllocator( const CacheAllocator& ) = delete;
    CacheAllocator( CacheAllocator&& ) = delete;
    CacheAllocator& operator=( const CacheAllocator& ) = delete;
    CacheAllocator& operator=( CacheAllocator&& ) = delete;

    static uint8_t* malloc() noexcept;
    static void free( void* ptr ) noexcept;
    static void gc(); ///< clear cache

private:
    static constexpr uint32_t CACHE_SIZE = 31; ///< number of slots in cache
    static CacheAllocator& instance();

    uint8_t* m_cache[CACHE_SIZE] = {nullptr}; // try to fit whole struct in cache line size (64 bytes)
    uint32_t m_busy_mask = 0; // if use busy slots counter here, it will work slower
};

template<size_t BUFFER_SIZE>
uint8_t* CacheAllocator<BUFFER_SIZE>::malloc() noexcept
{
    CacheAllocator& allocator = instance();

    if( allocator.m_busy_mask == 0 )
        return (uint8_t*)::malloc( BUFFER_SIZE );

    uint32_t index = __builtin_ctz( allocator.m_busy_mask );
    assert( index < CACHE_SIZE );

    uint8_t* ptr = nullptr;
    std::swap( ptr, allocator.m_cache[index] );
    allocator.m_busy_mask &= ~(1u << index);

    return ptr;
}

template<size_t BUFFER_SIZE>
void CacheAllocator<BUFFER_SIZE>::free( void* ptr ) noexcept
{
    CacheAllocator& allocator = instance();

    uint32_t last_busy_index = CACHE_SIZE;
    if( allocator.m_busy_mask != 0 )
        last_busy_index = __builtin_ctz( allocator.m_busy_mask );
    assert( last_busy_index <= CACHE_SIZE );

    if( last_busy_index == 0 )
    {
        ::free( ptr );
        return;
    }

    allocator.m_cache[last_busy_index - 1] = (uint8_t*)ptr;
    allocator.m_busy_mask |= (1u << (last_busy_index - 1));
}

template<size_t BUFFER_SIZE>
CacheAllocator<BUFFER_SIZE>::~CacheAllocator() noexcept
{
    for( auto& ptr : m_cache )
        ::free( ptr );
}

template<size_t BUFFER_SIZE>
CacheAllocator<BUFFER_SIZE>& CacheAllocator<BUFFER_SIZE>::instance()
{
    static thread_local CacheAllocator allocator;

    return allocator;
}

template<size_t BUFFER_SIZE>
void CacheAllocator<BUFFER_SIZE>::gc()
{
    CacheAllocator& allocator = instance();

    for( auto& ptr : allocator.m_cache )
        ::free( ptr );

    allocator.m_busy_mask = 0;
    for( auto& ptr : allocator.m_cache )
        ptr = nullptr;
}

}
