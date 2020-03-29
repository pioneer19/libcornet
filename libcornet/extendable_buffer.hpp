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
