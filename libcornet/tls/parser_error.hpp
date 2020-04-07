/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <libcornet/tls/types.hpp>

namespace pioneer19::cornet::tls13::record
{

enum class ParserErrno : uint32_t
{
    SUCCESS = 0,
    W_LOW_DATA_IN_NET_RECORD,   // buffer do not have enough data, need to read next record
    W_LOW_DATA_IN_HANDSHAKE,    // Handshake need more records concatenated

    E_CLIENT_HELLO_NO_SPACE_FOR_VERSION_OR_RANDOM,
    E_CLIENT_HELLO_NO_SPACE_FOR_LEGACY_SESSION_ID,
    E_CLIENT_HELLO_NO_SPACE_FOR_CIPHER_SUITES,
    E_CLIENT_HELLO_NO_SPACE_FOR_LEGACY_COMPRESSION_METHODS,
    E_CLIENT_HELLO_NO_SPACE_FOR_EXTENSIONS,

    E_SUPPORTED_VERSIONS_NO_SPACE,
    E_EXTENSION_SERVER_NAME_NO_SPACE,
    E_EXTENSION_SERVER_NAME_UNKNOWN_TYPE,
    E_EXTENSION_SUPPORTED_GROUPS_NO_SPACE,
    E_EXTENSION_SIGNATURE_ALGORITHMS_NO_SPACE,
    E_EXTENSION_KEY_SHARE_NO_SPACE,
    E_EXTENSION_KEY_EXCHANGE_MODES_NO_SPACE,

    E_SERVER_HELLO_NO_SPACE_FOR_VERSION_OR_RANDOM,
    E_SERVER_HELLO_NO_SPACE_FOR_LEGACY_SESSION_ID_ECHO,
    E_SERVER_HELLO_NO_SPACE_FOR_CIPHER_SUITE,
    E_SERVER_HELLO_NO_SPACE_FOR_LEGACY_COMPRESSION_METHOD,
    E_SERVER_HELLO_NO_SPACE_FOR_EXTENSIONS,
    E_ENCRYPTED_EXTENSIONS_NO_SPACE_FOR_ENCRYPTED_EXTENSIONS,
    E_CERTIFICATE_NO_SPACE_FOR_CERTIFICATE_REQUEST_CONTEXT,
    E_CERTIFICATE_NO_SPACE_FOR_CERTIFICATE_LIST,
    E_CERTIFICATE_NO_SPACE_FOR_CERTIFICATE_ENTRY,
    E_CERTIFICATE_NO_SPACE_FOR_CERTIFICATE_EXTENSIONS,
    E_CERTIFICATE_NO_SPACE_FOR_CERTIFICATE_VERIFY,

    E_ALERT_NO_SPACE,
};

class ParserError
{
public:
    ParserError() = default;
    ParserError( ParserErrno parser_errno ) noexcept : m_errno( parser_errno ) {}

    ParserError( const ParserError& )       = default;
    ParserError( ParserError&& )            = default;
    ParserError& operator=( const ParserError& ) = default;
    ParserError& operator=( ParserError&& ) = default;
    ~ParserError() = default;

    explicit operator bool() const noexcept { return m_errno != ParserErrno::SUCCESS; }

    [[nodiscard]]
    const char* message() const noexcept;
    [[nodiscard]]
    ParserErrno parse_errno() const noexcept { return m_errno; }

private:
    ParserErrno m_errno = ParserErrno::SUCCESS;
};

}
