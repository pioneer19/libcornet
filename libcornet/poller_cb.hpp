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
struct PollerCb
{
    std::experimental::coroutine_handle<> reader_coro_handle;
    std::experimental::coroutine_handle<> writer_coro_handle;
    void*    m_backlink  = nullptr;
    uint32_t events_mask = 0;

    void reset_bits( uint32_t bits_to_clear )
    { events_mask &= (~bits_to_clear); }
};

}
