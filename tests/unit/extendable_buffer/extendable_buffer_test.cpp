/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <string>
#include <iostream> // INFO: without this header doctest can fail link std::ostream operator<<()

#include <doctest/doctest.h>

#include <libcornet/extendable_buffer.hpp>
using pioneer19::ExtendableBuffer;

TEST_CASE("ExtendableBuffer tests")
{
    ExtendableBuffer buffer;

    REQUIRE( buffer.capacity() == 0 );
    REQUIRE( buffer.size() == 0 );
    REQUIRE( buffer.empty() );

    std::string initial_string = "test data";

    SUBCASE( "append will increase size" )
    {
        buffer.append( reinterpret_cast<const uint8_t*>(initial_string.data()), initial_string.size() );

        CHECK( buffer.size()     == initial_string.size() );
        CHECK( buffer.capacity() >= initial_string.size() );

        SUBCASE( "Buffer copy will have the same data" )
        {
            ExtendableBuffer buffer_copy = buffer;
            std::string copied_string { reinterpret_cast<const char*>(buffer_copy.data()), buffer_copy.size() };

            CHECK( buffer.size() == buffer_copy.size() );
            CHECK( copied_string == initial_string );

            buffer_copy.reset();
            CHECK( buffer_copy.size() == 0 );
        }
        SUBCASE( "Moved buffer will have the same data" )
        {
            ExtendableBuffer buffer_copy = std::move(buffer);
            std::string moved_string { reinterpret_cast<const char*>(buffer_copy.data()), buffer_copy.size() };

            CHECK( buffer_copy.size() == initial_string.size() );
            CHECK( moved_string == initial_string );
        }
        SUBCASE( "second append will increment size")
        {
            ExtendableBuffer buffer_copy = buffer;
            std::string second_string = "some more data";
            buffer_copy.append( reinterpret_cast<const uint8_t*>(second_string.data()), second_string.size());
            CHECK( buffer_copy.size() == initial_string.size() + second_string.size());

            std::string copied_string { reinterpret_cast<const char*>(buffer_copy.data()), buffer_copy.size() };
            CHECK( copied_string != initial_string );
            CHECK( copied_string == (initial_string + second_string) );

            SUBCASE( "Operator copy will copy data" )
            {
                buffer_copy = buffer;
                std::string op_copied_string { reinterpret_cast<const char*>(buffer_copy.data()), buffer_copy.size() };

                CHECK( buffer.size() == buffer_copy.size() );
                CHECK( op_copied_string == initial_string );
            }
            SUBCASE( "Move operator will move data" )
            {
                buffer_copy = std::move(buffer);
                std::string moved_string { reinterpret_cast<const char*>(buffer_copy.data()), buffer_copy.size() };

                CHECK( buffer_copy.size() == initial_string.size() );
                CHECK( moved_string == initial_string );
            }
        }
    }
}

TEST_CASE("ExtendableBuffer reserve")
{
    ExtendableBuffer buffer;

    REQUIRE( buffer.capacity() == 0 );
    REQUIRE( buffer.size() == 0 );
    REQUIRE( buffer.empty());

    uint32_t size_to_reserve = 2032;
    buffer.reserve( size_to_reserve );

    CHECK( buffer.capacity() >= size_to_reserve );
    CHECK( buffer.size() == 0 );
    CHECK( buffer.empty() );

    uint32_t big_size_to_reserve = 32*1024;
    buffer.reserve( big_size_to_reserve );

    CHECK( buffer.capacity() >= big_size_to_reserve );
    CHECK( buffer.size() == 0 );
    CHECK( buffer.empty() );
}
