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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <algorithm>

#include <libcornet/cache_allocator.hpp>

namespace pioneer19::cornet::tls13
{

template< bool INITIAL_ALLOCATE = true >
class TlsReadBufferTemplate
{
public:
    TlsReadBufferTemplate();
    TlsReadBufferTemplate( TlsReadBufferTemplate&& ) noexcept = default;
    TlsReadBufferTemplate& operator=( TlsReadBufferTemplate&& ) noexcept = default;
    ~TlsReadBufferTemplate() = default;

    TlsReadBufferTemplate( const TlsReadBufferTemplate& ) = delete;
    TlsReadBufferTemplate& operator=( const TlsReadBufferTemplate& ) = delete;

    void allocate();
    void release_if_empty();
    void conserve_head( uint16_t skip_head, uint16_t size, uint16_t skip_tail=0 ) noexcept;
    [[nodiscard]]
    uint8_t* conserved_data() noexcept;
    [[nodiscard]]
    uint16_t conserved_size() const noexcept;
    [[nodiscard]]
    uint8_t* head() noexcept;
    [[nodiscard]]
    uint16_t size() const noexcept;
    [[nodiscard]]
    uint8_t* tail() noexcept;
    [[nodiscard]]
    uint16_t tail_size() const noexcept;
    void erase_conserved();
    void consume_conserved( uint16_t size );
    void consume( uint16_t size );
    void produce( uint16_t size );
    void compact();

private:
    // max encrypted tls record size is sizeof(TlsPlaintext)+16K+256 bytes
    static constexpr size_t BUFFER_SIZE = 20*1024;

    uint16_t m_conserve_buffer_size = 0 ; ///< total conserve size == data_buffer offset
    uint16_t m_conserve_data_offset = 0;  ///< conserve data offset from buffer begin
    uint16_t m_data_offset = 0;           ///< offset to current data head in buffer
    uint16_t m_data_size = 0;             ///< size of user data in buffer
    // m_buffer will contain [conserved data, user data] and conserve size can change (initial =0)
    std::unique_ptr<uint8_t[]> m_buffer;
};

using TlsWriteBuffer = TlsReadBufferTemplate<true>;
using TlsReadBuffer  = TlsReadBufferTemplate<true>;

template<bool INITIAL_ALLOCATE>
TlsReadBufferTemplate<INITIAL_ALLOCATE>::TlsReadBufferTemplate()
{
    if constexpr (INITIAL_ALLOCATE)
        allocate();
}

template< bool INITIAL_ALLOCATE >
inline void TlsReadBufferTemplate<INITIAL_ALLOCATE>::allocate()
{
    if( m_buffer == nullptr )
        m_buffer.reset( CacheAllocator<BUFFER_SIZE>::malloc() );
}
template< bool INITIAL_ALLOCATE >
void TlsReadBufferTemplate<INITIAL_ALLOCATE>::release_if_empty()
{
    assert( m_buffer.get() != nullptr );
    if( size() == 0 )
        CacheAllocator<BUFFER_SIZE>::free( m_buffer.release() );
}

/**
 * move data from buffer to conserve and decrease user buffer size
 * @param skip_head user visible data offset relative to data()
 * @param size bytes to conserve
 */
template< bool INITIAL_ALLOCATE >
inline void TlsReadBufferTemplate<INITIAL_ALLOCATE>::conserve_head(
        uint16_t skip_head, uint16_t size, uint16_t skip_tail ) noexcept
{
    m_conserve_data_offset = m_data_offset + skip_head;
    m_conserve_buffer_size = m_conserve_data_offset + size;
    consume( skip_head + size + skip_tail );
}
/**
 * get conserved data pointer
 * @return conserved data pointer
 */
template< bool INITIAL_ALLOCATE >
inline uint8_t* TlsReadBufferTemplate<INITIAL_ALLOCATE>::conserved_data() noexcept
{
    assert( m_buffer.get() != nullptr );
    return m_buffer.get() + m_conserve_data_offset;
}
/**
 * conserved data size
 * @return conserved data size
 */
template< bool INITIAL_ALLOCATE >
inline uint16_t TlsReadBufferTemplate<INITIAL_ALLOCATE>::conserved_size() const noexcept
{
    return m_conserve_buffer_size - m_conserve_data_offset;
}

/**
 * get user data head
 * @return user data buffer head
 */
template< bool INITIAL_ALLOCATE >
inline uint8_t* TlsReadBufferTemplate<INITIAL_ALLOCATE>::head() noexcept
{
    assert( m_buffer.get() != nullptr );
    return m_buffer.get() + m_data_offset;
}
/**
 * user buffer data size available to consume
 */
template< bool INITIAL_ALLOCATE >
inline uint16_t TlsReadBufferTemplate<INITIAL_ALLOCATE>::size() const noexcept
{
    return m_data_size;
}
/**
 * get user buffer tail, where I can write new data
 */
template< bool INITIAL_ALLOCATE >
inline uint8_t* TlsReadBufferTemplate<INITIAL_ALLOCATE>::tail() noexcept
{
    return head() + size();
}
/**
 * get tail size available to write
 */
template< bool INITIAL_ALLOCATE >
inline uint16_t TlsReadBufferTemplate<INITIAL_ALLOCATE>::tail_size() const noexcept
{
    return BUFFER_SIZE - (m_data_offset + m_data_size);
}
/**
 * remove all conserved data
 */
template< bool INITIAL_ALLOCATE >
inline void TlsReadBufferTemplate<INITIAL_ALLOCATE>::erase_conserved()
{
    m_conserve_buffer_size = 0;
    m_conserve_data_offset = 0;
}
/**
 * remove header size bytes from conserved buffer
 * @param size
 */
template< bool INITIAL_ALLOCATE >
inline void TlsReadBufferTemplate<INITIAL_ALLOCATE>::consume_conserved( uint16_t size )
{
    if( size == m_conserve_buffer_size )
        erase_conserved();
    else
        m_conserve_data_offset += size;
}
/**
 * remove size bytes from user buffer
 * @param size
 */
template< bool INITIAL_ALLOCATE >
inline void TlsReadBufferTemplate<INITIAL_ALLOCATE>::consume( uint16_t size )
{
    m_data_offset += size;
    m_data_size   -= size;
}
/**
 * move user data to buffer head so tail_size() become bigger
 */
template< bool INITIAL_ALLOCATE >
inline void TlsReadBufferTemplate<INITIAL_ALLOCATE>::compact()
{
    if( m_data_offset == m_conserve_buffer_size )
        return;

    assert( m_buffer.get() != nullptr );
    std::copy_n( head(), m_data_size, m_buffer.get() + m_conserve_buffer_size );
    m_data_offset = m_conserve_buffer_size;
}
/**
 * increase available data size
 */
template< bool INITIAL_ALLOCATE >
inline void TlsReadBufferTemplate<INITIAL_ALLOCATE>::produce( uint16_t size )
{
    m_data_size += size;
}

}
