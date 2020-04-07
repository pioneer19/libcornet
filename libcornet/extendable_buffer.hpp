/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <memory>

namespace pioneer19
{

class ExtendableBuffer
{
public:
    ExtendableBuffer() = default;
    ExtendableBuffer( const ExtendableBuffer& );
    ExtendableBuffer( ExtendableBuffer&& ) noexcept;
    ExtendableBuffer& operator=( const ExtendableBuffer& );
    ExtendableBuffer& operator=( ExtendableBuffer&& ) noexcept;
    ~ExtendableBuffer() = default;

    [[nodiscard]] uint32_t capacity() const noexcept;
    [[nodiscard]] uint32_t size() const noexcept;
    [[nodiscard]] uint32_t empty() const noexcept;

    [[nodiscard]] uint8_t* data() const noexcept;

    void reserve( uint32_t min_size );
    void append( const uint8_t* data, size_t size );
    void reset() noexcept;

private:
    static constexpr uint32_t BLOCK_SIZE = 4096;
    static constexpr uint32_t new_buffer_size( uint32_t other_size ) noexcept;
    uint32_t allocate_and_copy(
            uint32_t new_size, const uint8_t* old_data, uint32_t old_size );

    std::unique_ptr<uint8_t[]> m_buffer;
    uint32_t m_capacity;
    uint32_t m_filled;
};

inline uint32_t ExtendableBuffer::capacity() const noexcept
{
    if( m_buffer )
        return m_capacity;

    return 0;
}

inline uint32_t ExtendableBuffer::size() const noexcept
{
    if( m_buffer )
        return m_filled;

    return 0;
}

inline uint32_t ExtendableBuffer::empty() const noexcept
{
    return !m_buffer || m_filled == 0;
}

inline uint8_t* ExtendableBuffer::data() const noexcept
{
    return m_buffer.get();
}

inline void ExtendableBuffer::reset() noexcept
{
    m_buffer.reset();
}

}
