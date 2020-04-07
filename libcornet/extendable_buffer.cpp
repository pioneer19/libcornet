/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <libcornet/extendable_buffer.hpp>

#include <algorithm>

namespace pioneer19
{

ExtendableBuffer::ExtendableBuffer( const ExtendableBuffer& other )
{
    if( other.m_buffer && other.m_filled > 0 )
    {
        m_capacity = allocate_and_copy( other.m_filled, other.m_buffer.get(), other.m_filled );
        m_filled = other.m_filled;
    }
}

ExtendableBuffer::ExtendableBuffer( ExtendableBuffer&& other ) noexcept
        :m_buffer( std::move( other.m_buffer ) )
         ,m_capacity( other.m_capacity )
         ,m_filled( other.m_filled )
{}

ExtendableBuffer& ExtendableBuffer::operator=( const ExtendableBuffer& other )
{
    if( &other == this )
        return *this;

    if( (!other.m_buffer) || (other.m_filled == 0) )
        m_buffer.reset();
    else
    {
        m_capacity = allocate_and_copy( other.m_filled, other.m_buffer.get(), other.m_filled );
        m_filled = other.m_filled;
    }

    return *this;
}

uint32_t ExtendableBuffer::allocate_and_copy(
        uint32_t new_size, const uint8_t* old_data, uint32_t old_size )
{
    uint32_t buffer_size = new_buffer_size( new_size );

    decltype(m_buffer) tmp_buffer { new uint8_t[ buffer_size ] };
    std::copy_n( old_data, old_size, tmp_buffer.get() );
    m_buffer.swap( tmp_buffer );

    return buffer_size;
}

constexpr uint32_t ExtendableBuffer::new_buffer_size( uint32_t other_size ) noexcept
{
    return ((other_size-1)/BLOCK_SIZE+1)*BLOCK_SIZE;
}

ExtendableBuffer& ExtendableBuffer::operator=( ExtendableBuffer&& other ) noexcept
{
    if( &other == this )
        return *this;

    m_buffer   = std::move( other.m_buffer );
    m_capacity = other.m_capacity;
    m_filled   = other.m_filled;

    return *this;
}

void ExtendableBuffer::reserve( uint32_t min_size )
{
    if( !m_buffer )
    {
        uint32_t buffer_size = new_buffer_size( min_size );
        m_buffer.reset( new uint8_t[ buffer_size ] );
        m_capacity = buffer_size;
        m_filled = 0;
    }
    else if( m_capacity < min_size )
    {
        m_capacity = allocate_and_copy( min_size, m_buffer.get(), m_filled );
    }
}

void ExtendableBuffer::append( const uint8_t* data, size_t size )
{
    if( !m_buffer )
    {
        m_capacity = allocate_and_copy( size, data, size );
        m_filled = size;
        return;
    }
    if( ( m_capacity - m_filled ) < size )
    {
        m_capacity = allocate_and_copy( m_filled + size, m_buffer.get(), m_filled );
    }

    std::copy_n( data, size, m_buffer.get() + m_filled );
    m_filled += size;
}

}
