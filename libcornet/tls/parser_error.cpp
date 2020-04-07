/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
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
