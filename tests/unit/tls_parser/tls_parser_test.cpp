/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <doctest/doctest.h>

#include <libcornet/tls/parser.hpp>

namespace record = pioneer19::cornet::tls13::record;

TEST_CASE("Parser test with empty plaintext data")
{
    const char tls_record[] = { 22 // type
                                ,0x03,0x03 // legacy_version
                                ,0x00, 0x00 // data length
                                };

    record::Parser parser;
    auto[bytes_parsed, err] = parser.parse_net_record<record::EmptyHook>( nullptr
            ,tls_record, sizeof( tls_record) );

    CHECK( err );
    REQUIRE( err.parse_errno() == record::ParserErrno::W_LOW_DATA_IN_HANDSHAKE );
}

TEST_CASE("Parser test with low data in tls plaintext")
{
    const char short_tls_record[] = {22 // type
    };

    record::Parser parser;
    auto[bytes_parsed, err] = parser.parse_net_record<record::EmptyHook>( nullptr
            ,short_tls_record, sizeof( short_tls_record ) );

    CHECK( err );
    REQUIRE( err.parse_errno() == record::ParserErrno::W_LOW_DATA_IN_NET_RECORD );
}
TEST_CASE("Parser test with low data in tls plaintext data")
{
    const char short_tls_record2[] = { 22 // type
                                       ,0x03,0x03 // legacy_version
                                       ,0x00, 0x10 // data length
                                       // no data
    };

    record::Parser parser;
    auto [bytes_parsed,err] = parser.parse_net_record<record::EmptyHook>( nullptr
            ,short_tls_record2, sizeof( short_tls_record2) );

    CHECK( err );
    REQUIRE( err.parse_errno() == record::ParserErrno::W_LOW_DATA_IN_NET_RECORD );
}

TEST_CASE( "Parser test with empty handshake" )
{
    const char tls_record[] = { 22 // handshake type
                                ,0x03,0x03 // legacy_version
                                ,0x00, 0x01 // data length
                                ,0x01 // ClientHello
    };

    record::Parser parser;
    auto[bytes_parsed, err] = parser.parse_net_record<record::EmptyHook>( nullptr
            ,tls_record, sizeof( tls_record) );

    CHECK( err );
    REQUIRE( err.parse_errno() == record::ParserErrno::W_LOW_DATA_IN_HANDSHAKE );
}
// ParserErrno::E_CLIENT_HELLO_NO_SPACE_FOR_RANDOM


//    SUBCASE( "append will increase size" )
//    {
