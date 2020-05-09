/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <cstdint>
#include <experimental/coroutine>

namespace pioneer19::cornet
{

struct RefCounted
{
    uint32_t m_ref = 1;

    void     add_reference() { ++m_ref; }
    uint32_t del_reference() { return --m_ref; }
};

struct PollerCb : private RefCounted
{
    uint32_t events_mask = 0;
    std::experimental::coroutine_handle<> reader_coro_handle;
    std::experimental::coroutine_handle<> writer_coro_handle;

    void reset_bits( uint32_t bits_to_clear )
    { events_mask &= (~bits_to_clear); }

    void process_event();
    void clean() { reader_coro_handle = nullptr; writer_coro_handle = nullptr; events_mask = 0; }
    static void rm_reference( PollerCb* poller_cb );
    using RefCounted::add_reference;

private:
    ~PollerCb() = default;
};

inline void PollerCb::rm_reference( PollerCb* poller_cb )
{
    if( poller_cb->del_reference() == 0 )
        delete poller_cb;
}

inline void PollerCb::process_event()
{
    if( (events_mask & EPOLLOUT) && writer_coro_handle )
        writer_coro_handle.resume();

    if( (events_mask & EPOLLIN) && reader_coro_handle )
        reader_coro_handle.resume();
}

}
