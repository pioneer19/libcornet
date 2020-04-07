/*
 * Copyright 2020 Alex Syrnikov <pioneer19@post.cz>
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is part of libcornet (https://github.com/pioneer19/libcornet).
 */

#pragma once

#include <arpa/inet.h>

#include <endian.h>
#include <array>
#include <algorithm>

namespace pioneer19::cornet::tls13::record
{
#pragma pack(push, 1)
/*
 * struct {
 *     ContentType type;
 *     ProtocolVersion legacy_record_version;
 *     uint16 length;
 *     opaque fragment[TLSPlaintext.length];
 * } TLSPlaintext;
 *
 * struct {
 *     opaque content[TLSPlaintext.length];
 *     ContentType type;
 *     uint8 zeros[length_of_padding];
 * } TLSInnerPlaintext;
 *
 * struct {
 *     ContentType opaque_type = application_data; // 23
 *     ProtocolVersion legacy_record_version = 0x0303; // TLS v1.2
 *     uint16 length;
 *     opaque encrypted_record[TLSCiphertext.length];
 * } TLSCiphertext;
 *
 */
enum class ContentType : uint8_t
{
    INVALID            = 0,
    CHANGE_CIPHER_SPEC = 20,
    ALERT              = 21,
    HANDSHAKE          = 22,
    APPLICATION_DATA   = 23,
};

constexpr static inline uint16_t net_uint16_num( const uint8_t* data )
{
    return ( data[1] << 8) + data[0];
}

// ProtocolVersion actually is not number, but array<uint8_t,2>
//using ProtocolVersion = uint16_t;
struct ProtocolVersion
{
    uint8_t v_data[2];

    [[nodiscard]]
    constexpr uint16_t num() const { return net_uint16_num(v_data); }
    constexpr bool operator==( const ProtocolVersion& other ) const
    { return (v_data[0] == other.v_data[0]) && (v_data[1] == other.v_data[1]); }
};
constexpr static ProtocolVersion PROTOCOL_VERSION_TLS10 = {0x03,0x01};
constexpr static ProtocolVersion PROTOCOL_VERSION_TLS12 = {0x03,0x03};
constexpr static ProtocolVersion PROTOCOL_VERSION_TLS13 = {0x03,0x04};

struct TlsPlaintext
{
    ContentType     type;
    ProtocolVersion legacy_record_version;
    uint16_t        length;
    // opaque fragment[TlsPlaintext.length];

    void init( ContentType record_type
            ,ProtocolVersion legacy_record_version = PROTOCOL_VERSION_TLS12 );
    void finalize( size_t content_size );

    [[nodiscard]]
    uint16_t host_length() const noexcept { return be16toh( length ); }
};
/*
 * struct {
 *     opaque content[TLSPlaintext.length];
 *     ContentType type;
 *     uint8 zeros[length_of_padding];
 * } TLSInnerPlaintext;
 *
 * struct {
 *     ContentType opaque_type = application_data; // 23
 *     ProtocolVersion legacy_record_version = 0x0303; // TLS v1.2
 *     uint16 length;
 *     opaque encrypted_record[TLSCiphertext.length];
 * } TLSCiphertext;
 */
struct TLSCiphertext
{
    ContentType     opaque_type; // = application_data; // 23
    ProtocolVersion legacy_record_version; // = 0x0303; // TLS v1.2
    uint16_t        m_length;
    // opaque encrypted_record[TLSCiphertext.length];

    void init( ContentType record_type = ContentType::APPLICATION_DATA
            ,ProtocolVersion legacy_version = PROTOCOL_VERSION_TLS12 );
    [[nodiscard]]
    uint16_t length() const noexcept { return be16toh(m_length); }
    void finalize( size_t content_size );
};

/*
 * enum {
 *     client_hello(1),
 *     server_hello(2),
 *     new_session_ticket(4),
 *     end_of_early_data(5),
 *     encrypted_extensions(8),
 *     certificate(11),
 *     certificate_request(13),
 *     certificate_verify(15),
 *     finished(20),
 *     key_update(24),
 *     message_hash(254),
 *     (255)
 * } HandshakeType;
 * struct {
 *     HandshakeType msg_type;    // handshake type
 *     uint24 length;             // remaining bytes in message
 *     select (Handshake.msg_type) {
 *         case client_hello:          ClientHello;
 *         case server_hello:          ServerHello;
 *         case end_of_early_data:     EndOfEarlyData;
 *         case encrypted_extensions:  EncryptedExtensions;
 *         case certificate_request:   CertificateRequest;
 *         case certificate:           Certificate;
 *         case certificate_verify:    CertificateVerify;
 *         case finished:              Finished;
 *         case new_session_ticket:    NewSessionTicket;
 *         case key_update:            KeyUpdate;
 *     };
 *     } Handshake;
 */
enum class HandshakeType : uint8_t
{
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    NEW_SESSION_TICKET = 4,
    END_OF_EARLY_DATA  = 5,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE          = 11,
    CERTIFICATE_REQUEST  = 13,
    CERTIFICATE_VERIFY   = 15,
    FINISHED     = 20,
    KEY_UPDATE   = 24,
    MESSAGE_HASH = 254,
};

struct Handshake
{
    HandshakeType msg_type;    /* handshake type */
    uint32_t      length : 24; /* remaining bytes in message */
    /* next will be data with size == length
     * select (Handshake.msg_type) {
        case client_hello:          ClientHello;
        case server_hello:          ServerHello;
        case end_of_early_data:     EndOfEarlyData;
        case encrypted_extensions:  EncryptedExtensions;
        case certificate_request:   CertificateRequest;
        case certificate:           Certificate;
        case certificate_verify:    CertificateVerify;
        case finished:              Finished;
        case new_session_ticket:    NewSessionTicket;
        case key_update:            KeyUpdate;
    };
    */

    void init( HandshakeType handshake_type );
    void finalize( uint32_t data_size );

    [[nodiscard]]
    uint32_t host_length() const noexcept { return be32toh( length ) >> 8u; }
};

// using Random = uint8_t[32];
using Random = std::array<uint8_t,32>;

//  opaque legacy_session_id<0..32>;
struct LegacySessionId
{
    uint8_t size;
    // opaque legacy_session_id<0..32>;
};
/*
 * TLS 1.3 cipher suites
 * +------------------------------+-------------+
 * | Description                  | Value       |
 * +------------------------------+-------------+
 * | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
 * | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
 * | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
 * | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
 * | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
 * +------------------------------+-------------+
 */
// uint8 CipherSuite[2];    /* Cryptographic suite selector */
struct CipherSuite
{
    uint8_t cipher[2];
    constexpr uint16_t num() const { return net_uint16_num(cipher); }
    constexpr bool operator==( const CipherSuite& other ) const
    { return (cipher[0] == other.cipher[0]) && (cipher[1] == other.cipher[1]); }
};
constexpr static CipherSuite TLS_AES_128_GCM_SHA256       = {0x13,0x01};
constexpr static CipherSuite TLS_AES_256_GCM_SHA384       = {0x13,0x02};
constexpr static CipherSuite TLS_CHACHA20_POLY1305_SHA256 = {0x13,0x03};
constexpr static CipherSuite TLS_AES_128_CCM_SHA256       = {0x13,0x04};
constexpr static CipherSuite TLS_AES_128_CCM_8_SHA256     = {0x13,0x05};
// Values with the first byte 255 (decimal) are reserved for Private Use
constexpr static CipherSuite TLS_PRIVATE_CIPHER_SUITE     = {0xFF,0xFF};

/*
 * uint16 ProtocolVersion;
 * opaque Random[32];
 * uint8 CipherSuite[2];    // Cryptographic suite selector
 * struct {
 *     ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *     Random random;
 *     opaque legacy_session_id<0..32>;
 *     CipherSuite cipher_suites<2..2^16-2>;
 *     opaque legacy_compression_methods<1..2^8-1>;
 *     Extension extensions<8..2^16-1>;
 * } ClientHello;
 */
struct ClientHello
{
    ProtocolVersion legacy_version; //= PROTOCOL_VERSION_TLS12;
    Random random;
    /*
    opaque legacy_session_id<0..32>;
    CipherSuite cipher_suites<2..2^16-2>;
    opaque legacy_compression_methods<1..2^8-1>;
    Extension extensions<8..2^16-1>;
    */
    uint16_t init( ProtocolVersion proto_legacy_version = PROTOCOL_VERSION_TLS12 );
};

/*
 * enum {
 *     server_name(0),                             // RFC 6066
 *     max_fragment_length(1),                     // RFC 6066
 *     status_request(5),                          // RFC 6066
 *     supported_groups(10),                       // RFC 8422, 7919
 *     signature_algorithms(13),                   // RFC 8446
 *     use_srtp(14),                               // RFC 5764
 *     heartbeat(15),                              // RFC 6520
 *     application_layer_protocol_negotiation(16), // RFC 7301
 *     signed_certificate_timestamp(18),           // RFC 6962
 *     client_certificate_type(19),                // RFC 7250
 *     server_certificate_type(20),                // RFC 7250
 *     padding(21),                                // RFC 7685
 *     pre_shared_key(41),                         // RFC 8446
 *     early_data(42),                             // RFC 8446
 *     supported_versions(43),                     // RFC 8446
 *     cookie(44),                                 // RFC 8446
 *     psk_key_exchange_modes(45),                 // RFC 8446
 *     certificate_authorities(47),                // RFC 8446
 *     oid_filters(48),                            // RFC 8446
 *     post_handshake_auth(49),                    // RFC 8446
 *     signature_algorithms_cert(50),              // RFC 8446
 *     key_share(51),                              // RFC 8446
 *     (65535)
 * } ExtensionType;
 */
enum class ExtensionType : uint16_t
{
    SERVER_NAME         = 0,
    MAX_FRAGMENT_LENGTH = 1,
    STATUS_REQUEST      = 5,
    SUPPORTED_GROUPS    = 10,
    SIGNATURE_ALGORITHMS = 13,
    USE_SRTP            = 14,
    HEARTBEAT           = 15,
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16,
    SIGNED_CERTIFICATE_TIMESTAMP = 18,
    CLIENT_CERTIFICATE_TYPE = 19,
    SERVER_CERTIFICATE_TYPE = 20,
    PADDING                 = 21,
    PRE_SHARED_KEY          = 41,
    EARLY_DATA              = 42,
    SUPPORTED_VERSIONS      = 43,
    COOKIE                  = 44,
    PSK_KEY_EXCHANGE_MODES  = 45,
    CERTIFICATE_AUTHORITIES = 47,
    OID_FILTERS             = 48,
    POST_HANDSHAKE_AUTH     = 49,
    SIGNATURE_ALGORITHMS_CERT = 50,
    KEY_SHARE               = 51,
};
 /*
  * struct {
  *     ExtensionType m_extension_type;
  *     opaque extension_data<0..2^16-1>;
  * } Extension;
  */
struct Extension
{
    uint16_t m_extension_type;
    uint16_t m_size;

    uint16_t init( ExtensionType type );
    void finalize( uint16_t data_size ) { m_size = htobe16( data_size ); }

    ExtensionType extension_type() const noexcept
    { return static_cast<ExtensionType>(be16toh(m_extension_type)); }
    [[nodiscard]]
    uint16_t size() const noexcept { return be16toh(m_size); }
};

struct ExtensionList
{
    uint16_t size; // size in bytes, not elements

    void finalize( uint16_t data_size ) { size = htobe16( data_size ); }
    [[nodiscard]]
    uint16_t host_size() const noexcept { return be16toh( size ); }

    void convert_from_network() { size = be16toh(size); }
};

/*
 * struct {
 *     NameType name_type;
 *     select (name_type) {
 *         case host_name: HostName;
 *     } name;
 * } ServerName;

 * enum {
 *     host_name(0), (255)
 * } NameType;

 * opaque HostName<1..2^16-1>;
 */
enum class NameType : uint8_t
{
    HOST_NAME = 0,
};
struct ServerName
{
    NameType name_type;
    // opaque HostName<1..2^16-1>;

    uint32_t init( NameType type = NameType::HOST_NAME ) { name_type = type; return sizeof(*this); }
    void convert_from_network() {}
};

// opaque HostName<1..2^16-1>;
struct HostName
{
    uint16_t size;

    void finalize( uint16_t data_size ) { size = htobe16( data_size ); }
    uint16_t host_size() const noexcept { return be16toh( size ); }

    void convert_from_network() { size = be16toh( size ); }
};

// extension of type "server_name" will contain ServerNameList
// in "extension_data" field
/*
 * struct {
 *     ServerName server_name_list<1..2^16-1>
 * } ServerNameList;
 */
struct ServerNameList
{
    uint16_t m_size;

    [[nodiscard]]
    uint16_t size() const noexcept { return be16toh(m_size); }
    ServerName* data();
    void finalize( uint16_t data_size ) { m_size = htobe16( data_size ); }
    void convert_from_network() { m_size = be16toh( m_size ); }
};

// supported groups for key exchange extension
enum class NamedGroup : uint16_t
{
    /* Elliptic Curve Groups (ECDHE) */
    SECP256R1 = 0x0017, SECP384R1 = 0x0018, SECP521R1 = 0x0019,
    X25519 = 0x001D, X448 = 0x001E,

    /* Finite Field Groups (DHE) */
    FFDHE2048 = 0x0100, FFDHE3072 = 0x0101, FFDHE4096 = 0x0102,
    FFDHE6144 = 0x0103, FFDHE8192 = 0x0104,

    /* Reserved Code Points */
    // FFDHE_PRIVATE_USE(0x01FC..0x01FF),
    // ECDHE_PRIVATE_USE(0xFE00..0xFEFF),
    TLS_PRIVATE_NAMED_GROUP = 0xFEFF,
};
// convert NamedGroup to network byte order
inline NamedGroup hton_named_group( NamedGroup n ) noexcept
{ return static_cast<NamedGroup>(htobe16(static_cast<uint16_t>(n)));}
// convert NamedGroup to host byte order
inline NamedGroup ntoh_named_group( NamedGroup n ) noexcept
{ return static_cast<NamedGroup>(be16toh(static_cast<uint16_t>(n)));}


// The "extension_data" field of supported_groups extension contains a
// "NamedGroupList" value
/*
 * struct {
 *     NamedGroup named_group_list<2..2^16-1>;
 * } NamedGroupList;
 */
struct NamedGroupList
{
    uint16_t m_size;
    //NamedGroup named_group_list<2..2^16-1>;

    uint16_t size() const noexcept { return be16toh( m_size ); }
    void finalize( uint16_t data_size ) { m_size = htobe16( data_size ); }
    void convert_from_network() { m_size = be16toh(m_size); }
};

// application_layer_protocol_negotiation extension will contain ProtocolNameList
/*
 * opaque ProtocolName<1..2^8-1>; // len_byte,"http/1.1"
 * struct {
 *     ProtocolName protocol_name_list<2..2^16-1>
 * } ProtocolNameList;
 */
struct ProtocolName
{
    uint8_t size;
    // opaque ProtocolName<1..2^8-1>;

    void finalize( uint8_t data_size ) { size = data_size; }
    void  convert_from_network() {}
};
// application_layer_protocol_negotiation extension will contain ProtocolNameList
struct ProtocolNameList
{
    uint16_t size;
    //ProtocolName protocol_name_list<2..2^16-1>

    void finalize( uint16_t data_size ) { size = htobe16( data_size ); }
    void convert_from_network() { size = be16toh(size); }
};

/*
 * "extension_data" field of "signature_algorithms"
 * and "signature_algorithms_cert" extensions contains a
 * SignatureSchemeList value:
 * enum {
 *     // RSASSA-PKCS1-v1_5 algorithms
 *     rsa_pkcs1_sha256(0x0401),
 *     rsa_pkcs1_sha384(0x0501),
 *     rsa_pkcs1_sha512(0x0601),
 *
 *     // ECDSA algorithms
 *     ecdsa_secp256r1_sha256(0x0403),
 *     ecdsa_secp384r1_sha384(0x0503),
 *     ecdsa_secp521r1_sha512(0x0603),
 *
 *     // RSASSA-PSS algorithms with public key OID rsaEncryption
 *     rsa_pss_rsae_sha256(0x0804),
 *     rsa_pss_rsae_sha384(0x0805),
 *     rsa_pss_rsae_sha512(0x0806),
 *
 *     // EdDSA algorithms
 *     ed25519(0x0807),
 *     ed448(0x0808),
 *
 *     // RSASSA-PSS algorithms with public key OID RSASSA-PSS
 *     rsa_pss_pss_sha256(0x0809),
 *     rsa_pss_pss_sha384(0x080a),
 *     rsa_pss_pss_sha512(0x080b),
 *
 *     // Legacy algorithms
 *     rsa_pkcs1_sha1(0x0201),
 *     ecdsa_sha1(0x0203),
 *     / Reserved Code Points
 *     private_use(0xFE00..0xFFFF),
 *     (0xFFFF)
 * } SignatureScheme;
 * struct {
 *     SignatureScheme supported_signature_algorithms<2..2^16-2>;
 * } SignatureSchemeList;
 */
struct SignatureScheme
{
    uint8_t data[2];

    [[nodiscard]]
    constexpr uint16_t num() const { return net_uint16_num(data); }
    constexpr bool operator==( const SignatureScheme& other ) const
    { return (data[0] == other.data[0]) && (data[1] == other.data[1]); }
};
/* RSASSA-PKCS1-v1_5 algorithms */
constexpr static SignatureScheme SIGNATURE_SCHEME_RSA_PKCS1_SHA256 = {0x04,0x01};
constexpr static SignatureScheme SIGNATURE_SCHEME_RSA_PKCS1_SHA384 = {0x05,0x01};
constexpr static SignatureScheme SIGNATURE_SCHEME_RSA_PKCS1_SHA512 = {0x06,0x01};
/* ECDSA algorithms */
constexpr static SignatureScheme SIGNATURES_SCHEME_ECDSA_SECP256R1_SHA256 = {0x04,0x03};
constexpr static SignatureScheme SIGNATURES_SCHEME_ECDSA_SECP384R1_SHA384 = {0x05,0x03};
constexpr static SignatureScheme SIGNATURES_SCHEME_ECDSA_SECP521R1_SHA512 = {0x06,0x03};
/* RSASSA-PSS algorithms with public key OID rsaEncryption */
constexpr static SignatureScheme SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256 = {0x08,0x04};
constexpr static SignatureScheme SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384 = {0x08,0x05};
constexpr static SignatureScheme SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512 = {0x08,0x06};
/* EdDSA algorithms */
constexpr static SignatureScheme SIGNATURE_SCHEME_ED25519 = {0x08,0x07};
constexpr static SignatureScheme SIGNATURE_SCHEME_ED448   = {0x08,0x08};
/* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
constexpr static SignatureScheme SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256 = {0x08,0x09};
constexpr static SignatureScheme SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384 = {0x08,0x0a};
constexpr static SignatureScheme SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512 = {0x08,0x0b};
/* Legacy algorithms */
constexpr static SignatureScheme SIGNATURE_SCHEME_RSA_PKCS1_SHA1 = {0x02,0x01};
constexpr static SignatureScheme SIGNATURE_SCHEME_ECDSA_SHA1     = {0x02,0x03};
// private use
constexpr static SignatureScheme SIGNATURE_SCHEME_PRIVATE        = {0xFF,0xFF};

// "extension_data" field of "signature_algorithms" will contain SignatureSchemeList
/* struct {
 *     SignatureScheme supported_signature_algorithms<2..2^16-2>;
 * } SignatureSchemeList;
 */
struct SignatureSchemeList
{
    uint16_t size;
    // SignatureScheme supported_signature_algorithms<2..2^16-2>;

    void  finalize( uint16_t content_size ) { size = htobe16(content_size); }
    void  convert_from_network() { size = be16toh( size ); }
};

// supported_versions extension_data
/*
 * struct {
 *     select (Handshake.msg_type) {
 *         case client_hello:
 *             ProtocolVersion versions<2..254>;
 *         case server_hello: // and HelloRetryRequest
 *             ProtocolVersion selected_version;
 *     };
 * } SupportedVersions;
 */
struct SupportedVersions
{
    uint8_t size;

    void  finalize( uint8_t data_size ) { size = data_size; }
    void  convert_from_network() {}
};

// psk_key_exchange_modes extension
/*
 * enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
 * struct {
 *     PskKeyExchangeMode ke_modes<1..255>;
 * } PskKeyExchangeModes;
 */
enum class PskKeyExchangeMode : uint8_t
{
    PSK_KE     = 0,
    PSK_DHE_KE = 1,
};

struct PskKeyExchangeModes
{
    uint8_t size;
    // PskKeyExchangeMode ke_modes<1..255>;

    void finalize( uint8_t content_size ) { size = content_size; }
    void convert_from_network(){}
};

/*
 * struct {
 *     NamedGroup group;
 *     opaque key_exchange<1..2^16-1>;
 * } KeyShareEntry;
 */
struct KeyShareEntry
{
    NamedGroup group;
    uint16_t   m_size;

    uint32_t init( NamedGroup named_group ) { group = hton_named_group(named_group); return sizeof(*this); }
    uint8_t* data() { return reinterpret_cast<uint8_t*>(this) + sizeof(*this); }
    [[nodiscard]]
    uint16_t size() const noexcept { return be16toh( m_size ); }
    void  finalize( uint16_t data_size ) { m_size = htobe16( data_size ); }
//    void  convert_from_network() { m_size = be16toh( m_size ); }
};

/* In the ClientHello message, the "extension_data" field of key_share
 * extension contains a "KeyShareClientHello" value:
 * struct {
 *     KeyShareEntry client_shares<0..2^16-1>;
 * } KeyShareClientHello;
 */
struct KeyShareClientHello
{
    uint16_t m_size;

    KeyShareEntry* data();
    void  finalize( uint16_t data_size ) { m_size = htobe16( data_size ); }

    [[nodiscard]]
    uint16_t size() const noexcept { return be16toh( m_size ); }
    void convert_from_network() { m_size = be16toh( m_size ); }
};

struct ServerHello
{
    ProtocolVersion legacy_version = PROTOCOL_VERSION_TLS12;
    Random          random;
//    opaque legacy_session_id_echo<0..32>;
//    CipherSuite cipher_suite;
//    uint8 legacy_compression_method = 0;
//    Extension extensions<6..2^16-1>;

    uint16_t init( ProtocolVersion proto_legacy_version = PROTOCOL_VERSION_TLS12 );
//    explicit ServerHello( const Random& rnd )
//            :random(rnd)
//    {}
};

inline uint16_t ServerHello::init( ProtocolVersion proto_legacy_version )
{
    legacy_version = proto_legacy_version;
    return sizeof(ClientHello);
}

/*
 * struct {
 *     Extension extensions<0..2^16-1>;
 * } EncryptedExtensions;
 */
struct EncryptedExtensions
{
    uint16_t m_size;

//    uint16_t init( ExtensionType type );
//    void finalize( uint16_t data_size ) { m_size = htobe16( data_size ); }

    [[nodiscard]]
    uint16_t size() const noexcept { return be16toh(m_size); }
};
/*
 * enum {
 *     X509(0),
 *     RawPublicKey(2),
 *     (255)
 * } CertificateType;
 * struct {
 *     select (certificate_type) {
 *         case RawPublicKey:
 *             // From RFC 7250 ASN.1_subjectPublicKeyInfo
 *             opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
 *         case X509:
 *             opaque cert_data<1..2^24-1>;
 *     };
 *     Extension extensions<0..2^16-1>;
 * } CertificateEntry;
 * struct {
 *     opaque certificate_request_context<0..2^8-1>;
 *     CertificateEntry certificate_list<0..2^24-1>;
 * } Certificate;
 */
enum class  CertificateType : uint8_t
{
    X509 = 0,
    RawPublicKey = 2,
};
struct NetUint24
{
    uint32_t      m_length : 24;
    NetUint24& operator=( uint32_t data_size ) { assign(data_size); return *this; }
    [[nodiscard]]
    uint32_t length() const noexcept { return be32toh( m_length ) >> 8u; }
    void assign( uint32_t data_size ) { m_length = htobe32( data_size ) >> 8u; }
    void finalize( uint32_t content_size ) { assign( content_size ); }
};
/*
 * struct {
 *     SignatureScheme algorithm;
 *     opaque signature<0..2^16-1>;
 * } CertificateVerify;
 */
struct CertificateVerify
{
    SignatureScheme algorithm;
    // opaque signature<0..2^16-1>;
};
/*
 * enum { warning(1), fatal(2), (255) } AlertLevel;
 * enum {
 *     close_notify(0),
 *     unexpected_message(10),
 *     bad_record_mac(20),
 *     record_overflow(22),
 *     handshake_failure(40),
 *     bad_certificate(42),
 *     unsupported_certificate(43),
 *     certificate_revoked(44),
 *     certificate_expired(45),
 *     certificate_unknown(46),
 *     illegal_parameter(47),
 *     unknown_ca(48),
 *     access_denied(49),
 *     decode_error(50),
 *     decrypt_error(51),
 *     protocol_version(70),
 *     insufficient_security(71),
 *     internal_error(80),
 *     inappropriate_fallback(86),
 *     user_canceled(90),
 *     missing_extension(109),
 *     unsupported_extension(110),
 *     unrecognized_name(112),
 *     bad_certificate_status_response(113),
 *     unknown_psk_identity(115),
 *     certificate_required(116),
 *     no_application_protocol(120),
 *     (255)
 * } AlertDescription;
 * struct {
 *     AlertLevel level;
 *     AlertDescription description;
 * } Alert;
 */
enum class AlertLevel : uint8_t
{
    WARNING = 1,
    FATAL   = 2,
};
enum class AlertDescription : uint8_t
{
    CLOSE_NOTIFY        = 0,
    UNEXPECTED_MESSAGE  = 10,
    BAD_RECORD_MAC      = 20,
    RECORD_OVERFLOW     = 22,
    HANDSHAKE_FAILURE   = 40,
    BAD_CERTIFICATE     = 42,
    UNSUPPORTED_CERTIFICATE = 43,
    CERTIFICATE_REVOKED = 44,
    CERTIFICATE_EXPIRED = 45,
    CERTIFICATE_UNKNOWN = 46,
    ILLEGAL_PARAMETER   = 47,
    UNKNOWN_CA          = 48,
    ACCESS_DENIED       = 49,
    DECODE_ERROR        = 50,
    DECRYPT_ERROR       = 51,
    PROTOCOL_VERSION    = 70,
    INSUFFICIENT_SECURITY = 71,
    INTERNAL_ERROR      = 80,
    INAPPROPRIATE_FALLBACK = 86,
    USER_CANCELED       = 90,
    MISSING_EXTENSION   = 109,
    UNSUPPORTED_EXTENSION = 110,
    UNRECOGNIZED_NAME   = 112,
    BAD_CERTIFICATE_STATUS_RESPONSE = 113,
    UNKNOWN_PSK_IDENTITY = 115,
    CERTIFICATE_REQUIRED = 116,
    NO_APPLICATION_PROTOCOL = 120,
};
struct Alert
{
    AlertLevel level;             // can be ignored in TLS 1.3
    AlertDescription description;
};

#pragma pack(pop)

inline void TlsPlaintext::init( ContentType record_type, ProtocolVersion protocol_version )
{
    type = record_type;
    legacy_record_version = protocol_version;
}

inline void TlsPlaintext::finalize( size_t content_size )
{
    length = htobe16( static_cast<uint16_t>(content_size) );
}

inline void TLSCiphertext::init( ContentType record_type, ProtocolVersion legacy_version )
{
    opaque_type = record_type;
    legacy_record_version = legacy_version;
}

inline void TLSCiphertext::finalize( size_t content_size )
{
    m_length = htobe16( static_cast<uint16_t>(content_size) );
}

inline void Handshake::init( HandshakeType handshake_type )
{
    msg_type = handshake_type;
}

inline void Handshake::finalize( uint32_t data_size )
{
    length = htobe32( data_size ) >> 8;
}

inline uint16_t ClientHello::init( ProtocolVersion proto_legacy_version )
{
    legacy_version = proto_legacy_version;
    return sizeof(ClientHello);
}

inline uint16_t Extension::init( ExtensionType type )
{
    m_extension_type = htobe16( static_cast<uint16_t>(type) );
    return sizeof(Extension);
}

inline ServerName* ServerNameList::data()
{
    return reinterpret_cast<ServerName*>(
            reinterpret_cast<uint8_t*>(this)+sizeof(ServerNameList) );
}

inline KeyShareEntry* KeyShareClientHello::data()
{
    return reinterpret_cast<KeyShareEntry*> (
            reinterpret_cast<char*>(this) + sizeof(*this) );
}

}
