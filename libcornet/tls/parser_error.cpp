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

#include <libcornet/tls/parser_error.hpp>

#include <string>

namespace pioneer19::cornet::tls13::record
{

const char* ParserError::message() const noexcept
{
    switch( m_errno )
    {
        case ParserErrno::SUCCESS:
            return "success";
        case ParserErrno::W_LOW_DATA_IN_NET_RECORD:
            return "low data, need to read more to parse";
        case ParserErrno::E_CLIENT_HELLO_NO_SPACE_FOR_VERSION_OR_RANDOM:
            return "not enough space for ClienHello legacy_version or random";
        default:
            throw std::runtime_error( "Parser::str_error got unknown errno "
                                      + std::to_string(static_cast<uint32_t>(m_errno) ) );
    }
}

}
