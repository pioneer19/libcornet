/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#include <libcornet/tls/tls_connector.hpp>
#include <libcornet/tls/tls_connector_template.cpp>

namespace pioneer19::cornet::tls13
{

template class TlsConnectorImpl<PRODUCTION_OS_SEAM>;

}
