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
