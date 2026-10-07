/*
---------------------------------------------------------------------------------
Yuma Masubuchi JPCERT/CC 
    Confirmed working on IDA 9.4 on Win11
---------------------------------------------------------------------------------
*/
#define PRINT_DEBUG true
#if defined(_WIN32) && !defined(_WIN64)
    // Case of the Windows 32bit
#else
    #define __EA64__
#endif

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstdint>
#include <exception>
#include <string>
#include <algorithm>
#include <utility>


// IDA SDK Library
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <xref.hpp>
#include <bytes.hpp>
#include <search.hpp>
#include <ua.hpp>

// Cryptopp Library
#include <sha.h>
#include <hmac.h>
#include <filters.h>

// ucl lib
#include <ucl.h>


static std::string formatHexDump(const std::vector<uint8_t>& data){
    const size_t bytePerLine = 16;
    std::ostringstream oss;

    for (size_t i = 0; i < data.size(); i += bytePerLine) {
        oss << std::setw(8) << std::setfill('0') << std::hex << i << ": ";

        for ( size_t j = 0; j < bytePerLine; ++j) {
            if ( i + j < data.size()) {
                oss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i + j]) << " ";
            } else {
                oss << "    ";
            }
        }
        oss << " ";
        for ( size_t j = 0; j < bytePerLine; ++j) {
            if (i + j < data.size() ){
                uint8_t byte = data[i + j];
                if (byte >= 32 && byte <= 126) {
                    oss << static_cast<char>(byte);
                } else {
                    oss << ".";
                }
            }
        }
        oss << "\n";
    }
    return oss.str();
}


static void xor_buffer(std::vector<uint8_t>& data, uint8_t xor_val) {
    for (auto& byte : data) {
        byte ^= xor_val;
    }
}


static std::vector<uint8_t> slice(const std::vector<uint8_t>& data, size_t start, size_t length) {
    if (start > data.size()) {
        start = data.size();
    }
    if (start + length > data.size()) {
        length = data.size() - start;
    }
    
    return std::vector<uint8_t>(data.begin() + start, data.begin() + start + length);
}


static uint32_t read_be16_to_uint32(const std::vector<uint8_t>& data, size_t index) {
    if (index + 1 >= data.size()) {
        throw std::out_of_range("Index out of range for 2-byte little^endian read");
    }
    return (static_cast<uint32_t>(data[index]) << 8) | (static_cast<uint32_t>(data[index+1]));
}

static uint32_t read_le16_to_uint32(const std::vector<uint8_t>& data, size_t index) {
    if (index + 1 >= data.size()) {
        throw std::out_of_range("Index out of range for 2-byte little^endian read");
    }
    return (static_cast<uint32_t>(data[index])) | (static_cast<uint32_t>(data[index+1]) << 8);
}


static void readBytes(uintptr_t address, size_t length) {
    unsigned char* bytePointer = reinterpret_cast<unsigned char*>(address);
    msg("Reading %d bytes from address 0x%x \n", length, address);
    for (size_t i = 0;i < length; ++i) {
        try {
            unsigned char value = *(bytePointer + i);
            msg("Byte[%d]: 0x%x\n", i, static_cast<int>(value));
        } catch (...){
            msg("[-] Error: unable to read memory at offset%d\n", i);
            break;
        }
    } 
    return;
}


static uint8_t calc_1byteChecksum(const std::vector<uint8_t>& data) {
    uint32_t sum = 0;
    for (uint8_t b : data) {
        sum += b;
    }
    return static_cast<uint8_t>(sum & 0xFF);
}


static std::vector<uint8_t> hmac_sha1_bytes(const std::string& key, const std::string& message) {
    using namespace CryptoPP;

    HMAC<SHA1> hmac(reinterpret_cast<const byte*>(key.data()), key.size());

    std::string mac;
    StringSource(message, true,
        new HashFilter(hmac,
            new StringSink(mac)
        )
    );
    return std::vector<uint8_t>(mac.begin(), mac.end());
}


static bool read_bytes_from_address(ea_t start_ea, size_t length, std::vector<uint8_t>& out_data) {
    out_data.resize(length);
    ssize_t read = get_bytes(out_data.data(), length, start_ea);
    if (read != ssize_t(length)){
        msg("[-] Failed to read bytes at %a (requested %zu, got %zd)\n", start_ea, length, read);
        out_data.clear();
        return false;
    }
    return true;
}


static ea_t find_binary_pattern(const std::string pattern) {
    ea_t start_ea = inf_get_min_ea();
    ea_t end_ea = inf_get_max_ea();
    return find_binary(start_ea, end_ea, pattern.c_str(), 16, SEARCH_DOWN);
}


static qstring get_function_name_by_address(ea_t addr) {
    func_t* func_stru = get_func(addr);
    if (func_stru == nullptr)
        return "<no function>";
    qstring name;
    if (get_func_name(&name, func_stru->start_ea) > 0)
        return name;

    return "<unnamed function>";
}


static ea_t get_function_start_ea(ea_t addr) {
    func_t* func = get_func(addr);
    if ( func == nullptr)
        return BADADDR;
    return func->start_ea;
}


/* Does not work this function */
static ea_t get_function_end_ea(ea_t addr) {
    func_t* func = get_func(addr);
    if ( func == nullptr)
        return BADADDR;
    return func->end_ea;
}


static uval_t get_operand_value(ea_t ea, uint8_t operand_num) {
    insn_t insn;
    if (decode_insn(&insn, ea) == 0)
        return BADADDR;
    return insn.ops[operand_num - 1].value;
}


static uval_t get_operand_address(ea_t ea, uint8_t operand_num) {
    insn_t insn;
    if (decode_insn(&insn, ea) == 0)
        return BADADDR;
    return insn.ops[operand_num - 1].addr;
}


static uint8_t read_byte_at(ea_t ea) {
    return uint8_t(get_byte(ea));
}


static ea_t get_pointer(ea_t ea) {
    if (inf_is_64bit())
        return get_dword(ea);
    else
        return get_wide_dword(ea);
}


static std::string detect_file_type() {
    filetype_t ft = inf_get_filetype();
    switch (ft)
    {
        case f_PE:
            return "PE";
        case f_ELF:
            return "ELF";
        default:
            return "None";
    }
    return "None";
}


static bool is_arm_architecture() {
    const processor_t *ph = get_ph();
    if ( ph == nullptr )
        return false;
    
    return ph->id == PLFM_ARM;
}


static std::vector<std::uint8_t> mal_decode(
    const std::vector<uint8_t>& encodedData,
    std::size_t encSize,
    uint8_t key)
{
    // Reject malformed sizes instead of indexing outside encodedData.
    if (encSize == 0 || encSize > encodedData.size()) {
        msg("[-] mal_decode: invalid input size (requested=%zu, available=%zu)\n",
            encSize, encodedData.size());
        return {};
    }

    std::vector<uint8_t> decodedData(encSize);
    std::uint8_t temp = 0;

    // This form avoids the unsigned-size_t underflow pattern used by
    // "i != -1" while preserving the reverse traversal.
    for (std::size_t i = encSize; i-- > 0; ) {
        temp = static_cast<std::uint8_t>(encodedData[i] - key);
        decodedData[i] = temp;
        if (i != 0) {
            decodedData[i] = static_cast<std::uint8_t>(temp - encodedData[i - 1]);
        }
    }
    return decodedData;
}

static void test_ucl() {
    if (ucl_init() != UCL_E_OK) {
        msg("[-] ucl init failed.");
    }
    msg("[+] ucl init successfully.");
    return;
}


bool decompressUCL(const std::vector<uint8_t>& compressed, std::vector<uint8_t>& decompressed, size_t expectedSize) {
    decompressed.clear();

    if (compressed.empty() || expectedSize == 0) {
        msg("[-] UCL decompression skipped: empty input or zero output size.\n");
        return false;
    }

    decompressed.resize(expectedSize);

    ucl_uint src_len = static_cast<ucl_uint>(compressed.size());
    ucl_uint dest_len = static_cast<ucl_uint>(expectedSize);

    int result = ucl_nrv2b_decompress_8( // ucl_nrv2b_decompress_8(
        compressed.data(),
        src_len,
        decompressed.data(),
        &dest_len,
        nullptr
    );

    if (result != UCL_E_OK) {
        msg("[-] UCL decompression failed (error=%d).\n", result);
        decompressed.clear();
        return false;
    }

    decompressed.resize(dest_len);
    return true;
}


static uint8_t GenerateKey(std::string key, std::string message) {
    std::vector<uint8_t> macbytes = hmac_sha1_bytes(key, message);


    if ( PRINT_DEBUG ) {
        std::string hexdump_raw = formatHexDump(macbytes);
        msg("[+] Sha1 HMac value:\n%s\n", hexdump_raw.c_str() );
    }

    uint8_t checksum = calc_1byteChecksum(macbytes);

    if ( PRINT_DEBUG )
        msg("[+] checksum: 0x%x\n", checksum );

    return checksum;
}



/* ============================================================================================
   ShortLeash decompressed config parser

   The decompressed blob is encoded as a Protocol Buffers-compatible wire stream.
   This parser intentionally does not require generated protobuf classes.  It walks
   length-delimited fields recursively and extracts artifacts useful during malware
   analysis: PEM certificates, private keys, printable strings, 20-byte identifiers,
   and C2 endpoints such as tcp://host:port.
============================================================================================ */

#define PRINT_EXTRACTED_PRIVATE_KEYS true
#define PRINT_UNKNOWN_CONFIG_FIELDS true

struct ProtoField
{
    uint32_t number = 0;
    uint8_t wire_type = 0;
    size_t tag_offset = 0;
    size_t payload_offset = 0;
    uint64_t varint_value = 0;
    std::vector<uint8_t> bytes;
};

struct ConfigExtractStats
{
    size_t certificate_count = 0;
    size_t private_key_count = 0;
    size_t c2_count = 0;
};

static bool read_proto_varint(const std::vector<uint8_t>& data, size_t& pos, uint64_t& value)
{
    value = 0;
    uint32_t shift = 0;

    for (int i = 0; i < 10; ++i)
    {
        if (pos >= data.size())
            return false;

        uint8_t b = data[pos++];
        value |= (static_cast<uint64_t>(b & 0x7F) << shift);

        if ((b & 0x80) == 0)
            return true;

        shift += 7;
    }

    return false;
}

static bool parse_proto_message(const std::vector<uint8_t>& data, std::vector<ProtoField>& fields)
{
    fields.clear();
    size_t pos = 0;

    while (pos < data.size())
    {
        ProtoField field;
        field.tag_offset = pos;

        uint64_t tag = 0;
        if (!read_proto_varint(data, pos, tag))
            return false;

        field.number = static_cast<uint32_t>(tag >> 3);
        field.wire_type = static_cast<uint8_t>(tag & 0x07);

        if (field.number == 0)
            return false;

        switch (field.wire_type)
        {
            case 0: // varint
            {
                if (!read_proto_varint(data, pos, field.varint_value))
                    return false;
                break;
            }

            case 1: // fixed64
            {
                if (data.size() - pos < 8)
                    return false;
                field.payload_offset = pos;
                field.bytes.assign(data.begin() + pos, data.begin() + pos + 8);
                pos += 8;
                break;
            }

            case 2: // length-delimited
            {
                uint64_t length64 = 0;
                if (!read_proto_varint(data, pos, length64))
                    return false;

                if (length64 > static_cast<uint64_t>(data.size() - pos))
                    return false;

                size_t length = static_cast<size_t>(length64);
                field.payload_offset = pos;
                field.bytes.assign(data.begin() + pos, data.begin() + pos + length);
                pos += length;
                break;
            }

            case 5: // fixed32
            {
                if (data.size() - pos < 4)
                    return false;
                field.payload_offset = pos;
                field.bytes.assign(data.begin() + pos, data.begin() + pos + 4);
                pos += 4;
                break;
            }

            default:
                return false;
        }

        fields.push_back(std::move(field));
    }

    return !fields.empty();
}

static std::string bytes_to_hex(const std::vector<uint8_t>& data, bool with_spaces = false)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (size_t i = 0; i < data.size(); ++i)
    {
        if (with_spaces && i != 0)
            oss << ' ';
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }

    return oss.str();
}

static bool bytes_start_with(const std::vector<uint8_t>& data, const std::string& prefix)
{
    if (data.size() < prefix.size())
        return false;

    return std::equal(prefix.begin(), prefix.end(), data.begin());
}

static bool is_printable_ascii_blob(const std::vector<uint8_t>& data)
{
    if (data.empty())
        return false;

    size_t printable = 0;
    for (uint8_t b : data)
    {
        if ((b >= 0x20 && b <= 0x7E) || b == '\r' || b == '\n' || b == '\t')
            ++printable;
    }

    // Avoid treating mostly-binary blobs as strings.
    return (printable * 100 / data.size()) >= 95;
}

static bool is_c2_endpoint(const std::string& value)
{
    static const char* prefixes[] = {
        "tcp://", "udp://", "http://", "https://", "tls://", "ssl://"
    };

    for (const char* prefix : prefixes)
    {
        if (value.rfind(prefix, 0) == 0)
            return true;
    }

    return false;
}

static void print_c2_endpoint(const std::string& field_path, const std::string& endpoint)
{
    msg("[+] C2 Endpoint [field %s]: %s\n", field_path.c_str(), endpoint.c_str());

    size_t scheme_end = endpoint.find("://");
    if (scheme_end == std::string::npos)
        return;

    std::string scheme = endpoint.substr(0, scheme_end);
    std::string authority = endpoint.substr(scheme_end + 3);

    size_t slash = authority.find('/');
    if (slash != std::string::npos)
        authority = authority.substr(0, slash);

    std::string host = authority;
    std::string port;

    if (!authority.empty() && authority[0] == '[')
    {
        // IPv6 literal: scheme://[2001:db8::1]:443
        size_t close = authority.find(']');
        if (close != std::string::npos)
        {
            host = authority.substr(1, close - 1);
            if (close + 1 < authority.size() && authority[close + 1] == ':')
                port = authority.substr(close + 2);
        }
    }
    else
    {
        size_t colon = authority.rfind(':');
        if (colon != std::string::npos && colon + 1 < authority.size())
        {
            std::string candidate_port = authority.substr(colon + 1);
            bool all_digits = !candidate_port.empty();
            for (char c : candidate_port)
            {
                if (c < '0' || c > '9')
                {
                    all_digits = false;
                    break;
                }
            }

            if (all_digits)
            {
                host = authority.substr(0, colon);
                port = candidate_port;
            }
        }
    }

    msg("    Protocol : %s\n", scheme.c_str());
    msg("    Host     : %s\n", host.c_str());
    if (!port.empty())
        msg("    Port     : %s\n", port.c_str());
}

static void print_pem_artifact(
    const std::string& kind,
    const std::string& field_path,
    const std::vector<uint8_t>& data,
    size_t index)
{
    std::string pem(data.begin(), data.end());
    msg("[+] %s #%zu [field %s] (%zu bytes):\n%s\n",
        kind.c_str(), index, field_path.c_str(), data.size(), pem.c_str());
}

static void scan_shortleash_proto(
    const std::vector<uint8_t>& data,
    const std::string& prefix,
    size_t base_offset,
    int depth,
    ConfigExtractStats& stats)
{
    if (depth > 8)
        return;

    std::vector<ProtoField> fields;
    if (!parse_proto_message(data, fields))
        return;

    for (const ProtoField& field : fields)
    {
        std::string field_path = prefix.empty()
            ? std::to_string(field.number)
            : prefix + "." + std::to_string(field.number);

        if (field.wire_type == 0)
        {
            if (PRINT_UNKNOWN_CONFIG_FIELDS)
            {
                msg("[+] Varint [field %s] @ 0x%zx: %llu\n",
                    field_path.c_str(),
                    base_offset + field.tag_offset,
                    static_cast<unsigned long long>(field.varint_value));
            }
            continue;
        }

        if (field.wire_type != 2)
        {
            if (PRINT_UNKNOWN_CONFIG_FIELDS)
            {
                msg("[+] Binary [field %s] @ 0x%zx: %zu bytes\n",
                    field_path.c_str(),
                    base_offset + field.payload_offset,
                    field.bytes.size());
            }
            continue;
        }

        if (bytes_start_with(field.bytes, "-----BEGIN CERTIFICATE-----"))
        {
            ++stats.certificate_count;
            print_pem_artifact("Certificate", field_path, field.bytes, stats.certificate_count);
            continue;
        }

        if (bytes_start_with(field.bytes, "-----BEGIN PRIVATE KEY-----") ||
            bytes_start_with(field.bytes, "-----BEGIN RSA PRIVATE KEY-----") ||
            bytes_start_with(field.bytes, "-----BEGIN EC PRIVATE KEY-----"))
        {
            ++stats.private_key_count;
            if (PRINT_EXTRACTED_PRIVATE_KEYS)
                print_pem_artifact("Private Key", field_path, field.bytes, stats.private_key_count);
            else
                msg("[+] Private Key #%zu [field %s]: %zu bytes (output disabled)\n",
                    stats.private_key_count, field_path.c_str(), field.bytes.size());
            continue;
        }

        // First try to interpret a length-delimited field as a nested protobuf message.
        // This is what exposes field 8.2 as the C2 endpoint in the supplied sample.
        std::vector<ProtoField> nested;
        if (parse_proto_message(field.bytes, nested))
        {
            scan_shortleash_proto(
                field.bytes,
                field_path,
                base_offset + field.payload_offset,
                depth + 1,
                stats);
            continue;
        }

        if (is_printable_ascii_blob(field.bytes))
        {
            std::string value(field.bytes.begin(), field.bytes.end());

            if (is_c2_endpoint(value))
            {
                ++stats.c2_count;
                print_c2_endpoint(field_path, value);
            }
            else
            {
                msg("[+] String [field %s] @ 0x%zx: %s\n",
                    field_path.c_str(),
                    base_offset + field.payload_offset,
                    value.c_str());
            }
            continue;
        }

        if (field.bytes.size() == 20)
        {
            std::string hex = bytes_to_hex(field.bytes, false);
            msg("[+] 20-byte value [field %s] @ 0x%zx: %s\n",
                field_path.c_str(),
                base_offset + field.payload_offset,
                hex.c_str());
            continue;
        }

        if (PRINT_UNKNOWN_CONFIG_FIELDS)
        {
            msg("[+] Binary [field %s] @ 0x%zx: %zu bytes",
                field_path.c_str(),
                base_offset + field.payload_offset,
                field.bytes.size());

            if (field.bytes.size() <= 64)
            {
                std::string hex = bytes_to_hex(field.bytes, true);
                msg(" = %s", hex.c_str());
            }
            msg("\n");
        }
    }
}

static void parse_and_print_shortleash_config(const std::vector<uint8_t>& decompressedData)
{
    msg("\n[+] ============================================================\n");
    msg("[+] Parsed ShortLeash Configuration\n");
    msg("[+] ============================================================\n");

    std::vector<ProtoField> root_fields;
    if (!parse_proto_message(decompressedData, root_fields))
    {
        msg("[-] The decompressed data is not a valid protobuf-compatible message.\n");
        return;
    }

    ConfigExtractStats stats;
    scan_shortleash_proto(decompressedData, "", 0, 0, stats);

    msg("[+] ------------------------------------------------------------\n");
    msg("[+] Certificates : %zu\n", stats.certificate_count);
    msg("[+] Private keys : %zu\n", stats.private_key_count);
    msg("[+] C2 endpoints : %zu\n", stats.c2_count);
    msg("[+] ============================================================\n\n");
}

static bool validate_decoded_config(const std::vector<uint8_t>& decompressedData)
{
    if (decompressedData.empty())
        return false;

    // Treat the decoder as successful only when the decompressed bytes form a
    // structurally valid protobuf-compatible ShortLeash configuration.
    std::vector<ProtoField> root_fields;
    return parse_proto_message(decompressedData, root_fields);
}

static bool decode_config(
    const std::vector<uint8_t>& EncodedData,
    size_t len,
    std::vector<uint8_t>& outDecompressedData)
{
    outDecompressedData.clear();

    try {
        if (EncodedData.empty() || len == 0 || len > EncodedData.size()) {
            msg("[-] Standard decoder: invalid encoded data size.\n");
            return false;
        }

        const size_t size01 = 0x13FF;
        if (len < size01 || EncodedData.size() < size01) {
            msg("[-] Standard decoder: encoded data is too short (need 0x%zx bytes).\n", size01);
            return false;
        }

        const uint8_t key01 = EncodedData[len - 1];
        const uint8_t key02 = GenerateKey("ff", "");

        if (PRINT_DEBUG)
            msg("[+] Standard decoder key01: 0x%x\n", key01);

        auto decoded_1st = mal_decode(EncodedData, size01, key01);
        if (decoded_1st.size() != size01) {
            msg("[-] Standard decoder: first-stage decode failed.\n");
            return false;
        }

        if (PRINT_DEBUG) {
            std::string hexdump_raw = formatHexDump(decoded_1st);
            msg("[+] Standard decoder - Decoded 1st Config Data:\n%s\n", hexdump_raw.c_str());
        }

        if (decoded_1st.size() < 2) {
            msg("[-] Standard decoder: first-stage buffer is too short.\n");
            return false;
        }

        const size_t size02 = read_be16_to_uint32(decoded_1st, size01 - 2);
        const size_t slice_offset = 0xC;

        if (PRINT_DEBUG)
            msg("[+] Standard decoder size02: 0x%zx\n", size02);

        if (size02 <= slice_offset || size02 > decoded_1st.size()) {
            msg("[-] Standard decoder: invalid second-stage size 0x%zx.\n", size02);
            return false;
        }

        auto decoded_2nd = mal_decode(decoded_1st, size02, key02);
        if (decoded_2nd.size() != size02) {
            msg("[-] Standard decoder: second-stage decode failed.\n");
            return false;
        }

        if (PRINT_DEBUG) {
            std::string hexdump_raw = formatHexDump(decoded_2nd);
            msg("[+] Standard decoder - Decoded 2nd Config Data:\n%s\n", hexdump_raw.c_str());
        }

        std::vector<uint8_t> compressed(
            decoded_2nd.begin() + slice_offset,
            decoded_2nd.end());

        if (PRINT_DEBUG) {
            std::string hexdump_raw = formatHexDump(compressed);
            msg("[+] Standard decoder - UCL input:\n%s\n", hexdump_raw.c_str());
        }

        constexpr size_t originalSize = 20000;
        std::vector<uint8_t> decompressedData;
        if (!decompressUCL(compressed, decompressedData, originalSize)) {
            msg("[-] Standard decoder: UCL decompression failed.\n");
            return false;
        }

        if (!validate_decoded_config(decompressedData)) {
            msg("[-] Standard decoder: decompressed data failed configuration validation.\n");
            return false;
        }

        outDecompressedData = std::move(decompressedData);
        return true;
    }
    catch (const std::exception& e) {
        msg("[-] Standard decoder exception: %s\n", e.what());
    }
    catch (...) {
        msg("[-] Standard decoder: unexpected exception.\n");
    }

    outDecompressedData.clear();
    return false;
}

/* ============================================================================================
============================================================================================ */

static bool decode_config_variant(
    const std::vector<uint8_t>& EncodedData,
    size_t len,
    std::vector<uint8_t>& outDecompressedData)
{
    outDecompressedData.clear();

    try {
        const size_t size01 = 0x1400;
        const size_t parsed_size_offset = 0x2;
        const size_t slice_offset = 0xC;
        const size_t decoded_size = size01 - parsed_size_offset;

        if (EncodedData.size() < size01 || len < size01) {
            msg("[-] Variant decoder: encoded data is too short (need 0x%zx bytes).\n", size01);
            return false;
        }

        const uint8_t key = GenerateKey("ff", "");
        const size_t parsed_size = read_be16_to_uint32(EncodedData, 0x0);

        if (PRINT_DEBUG)
            msg("[+] Variant decoder parsed_size: 0x%zx\n", parsed_size);

        // Check before subtraction/slicing.  This prevents size_t underflow and
        // iterator construction outside the vector for malformed samples.
        if (parsed_size <= slice_offset || parsed_size > decoded_size) {
            msg("[-] Variant decoder: invalid parsed_size 0x%zx (max 0x%zx).\n",
                parsed_size, decoded_size);
            return false;
        }

        std::vector<uint8_t> parsed_EncodedData(
            EncodedData.begin() + parsed_size_offset,
            EncodedData.begin() + size01);

        auto decoded_1st = mal_decode(parsed_EncodedData, decoded_size, key);
        if (decoded_1st.size() != decoded_size) {
            msg("[-] Variant decoder: first-stage decode failed.\n");
            return false;
        }

        if (PRINT_DEBUG) {
            std::string hexdump_raw = formatHexDump(decoded_1st);
            msg("[+] Variant decoder - Decoded 1st Config Data:\n%s\n", hexdump_raw.c_str());
        }

        std::vector<uint8_t> compressed(
            decoded_1st.begin() + slice_offset,
            decoded_1st.begin() + parsed_size);

        if (PRINT_DEBUG) {
            std::string hexdump_raw = formatHexDump(compressed);
            msg("[+] Variant decoder - UCL input:\n%s\n", hexdump_raw.c_str());
        }

        constexpr size_t originalSize = 20000;
        std::vector<uint8_t> decompressedData;
        if (!decompressUCL(compressed, decompressedData, originalSize)) {
            msg("[-] Variant decoder: UCL decompression failed.\n");
            return false;
        }

        if (!validate_decoded_config(decompressedData)) {
            msg("[-] Variant decoder: decompressed data failed configuration validation.\n");
            return false;
        }

        outDecompressedData = std::move(decompressedData);
        return true;
    }
    catch (const std::exception& e) {
        msg("[-] Variant decoder exception: %s\n", e.what());
    }
    catch (...) {
        msg("[-] Variant decoder: unexpected exception.\n");
    }

    outDecompressedData.clear();
    return false;
}

static bool decode_config_auto(
    const std::vector<uint8_t>& EncodedData,
    size_t len,
    std::vector<uint8_t>& outDecompressedData)
{
    outDecompressedData.clear();

    // Variant configs begin with a big-endian decoded-size value.  Use that
    // only to choose the first decoder to try; it is not trusted as proof of
    // format.  Whichever decoder is tried first, failure always falls back to
    // the other decoder.
    bool variant_header_plausible = false;
    size_t variant_parsed_size = 0;

    if (EncodedData.size() >= 2) {
        variant_parsed_size =
            (static_cast<size_t>(EncodedData[0]) << 8) |
            static_cast<size_t>(EncodedData[1]);

        const size_t variant_max_size = 0x1400 - 0x2;
        variant_header_plausible =
            variant_parsed_size > 0xC &&
            variant_parsed_size <= variant_max_size;
    }

    if (variant_header_plausible) {
        msg("[+] Variant header looks plausible (parsed_size=0x%zx).\n",
            variant_parsed_size);
        msg("[+] Trying ShortLeash variant decoder first...\n");

        if (decode_config_variant(EncodedData, len, outDecompressedData)) {
            msg("[+] Decoder selected: ShortLeash variant\n");
            return true;
        }

        msg("[-] Variant decoder failed. Trying standard ShortLeash decoder...\n");
        outDecompressedData.clear();

        if (decode_config(EncodedData, len, outDecompressedData)) {
            msg("[+] Decoder selected: standard ShortLeash\n");
            return true;
        }
    }
    else {
        msg("[+] Variant header is not plausible. Trying standard ShortLeash decoder first...\n");

        if (decode_config(EncodedData, len, outDecompressedData)) {
            msg("[+] Decoder selected: standard ShortLeash\n");
            return true;
        }

        msg("[-] Standard decoder failed. Trying ShortLeash variant decoder...\n");
        outDecompressedData.clear();

        if (decode_config_variant(EncodedData, len, outDecompressedData)) {
            msg("[+] Decoder selected: ShortLeash variant\n");
            return true;
        }
    }

    outDecompressedData.clear();
    msg("[-] All ShortLeash config decoders failed.\n");
    return false;
}

static ea_t get_operand_target_ea(ea_t ea, int opnum)
{
    insn_t insn;
    if (decode_insn(&insn, ea) == 0)
        return BADADDR;

    if (opnum < 0 || opnum >= UA_MAXOP)
        return BADADDR;

    const op_t &op = insn.ops[opnum];

    if (op.type == o_void)
        return BADADDR;

    switch (op.type)
    {
    case o_mem:
    case o_near:
    case o_far:
        return op.addr;

    default:
        break;
    }


    if (opnum == 1)
    {
        ea_t dref = get_first_dref_from(ea);
        if (dref != BADADDR)
            return dref;
    }

    xrefblk_t xb;
    for (bool ok = xb.first_from(ea, XREF_DATA); ok; ok = xb.next_from())
    {
        if (xb.to != BADADDR)
            return xb.to;
    }

    return BADADDR;
}

ea_t get_second_operand_target_ea(ea_t ea)
{
    return get_operand_target_ea(ea, 1);
}

static void ShortLeash_ConfigExtracter(void) {
    msg("[+] Start ShortLeash config extractor\n");

    std::string func_pattern;
    int8_t offset;
    if ( detect_file_type() == "PE") {
        /*
        41 B8 00 14 00 00      mov     r8d, 1400h
        48 8D 15 B9 5F 0D 00   lea     rdx, EncodedConfig
        */
        func_pattern = "41 B8 00 14 00 00";
        offset = 0x6;
    } else if( detect_file_type() == "ELF") {
        if ( is_arm_architecture() ) {
            /*
            19 10 40 E3    MOVT   R1, #:upper16:unk_19DC74
            05 2B A0 E3    MOV    R2, #0x1400
            */
            msg("[+] ARM architecture!!\n");
            func_pattern = "05 2B A0 E3";
            offset = -4;

        } else { 
            /*
            BA 00 14 00 00         mov     edx, 1400h
            48 8D 35 B4 04 30 00   lea     rsi, EncodedConfig
            */
            func_pattern = "BA 00 14 00 00";
            offset = 0x5;
        }
    } else {
        msg("[-] File type does not detected!!\n");
        return;
    }

    ea_t config_inst_addr = find_binary_pattern(func_pattern);
    if (config_inst_addr != BADADDR) {
        qstring func_name = get_function_name_by_address(config_inst_addr);
        if ( PRINT_DEBUG )
            msg("[+] Found 0x%a: %s\n", config_inst_addr, func_name.c_str());
    } else {
        msg("[-] Not Found\n");
        return;
    }

    if ( PRINT_DEBUG )
        msg("[+] config_inst_addr + offset: 0x%a\n", config_inst_addr + offset);

    //ea_t operand_address = get_operand_address(config_inst_addr + offset , 2); // does not work for arm
    ea_t operand_address = get_second_operand_target_ea(config_inst_addr + offset);

    if ( PRINT_DEBUG )
        msg("[+] operand_address: 0x%a\n", operand_address);

    if (operand_address == BADADDR) {
        msg("[-] Failed to resolve encoded configuration address.\n");
        return;
    }

    ea_t config_addr = operand_address;

    size_t len = 0x1400;
    std::vector<uint8_t> EncodedConfig;

    if (!read_bytes_from_address(config_addr, len, EncodedConfig)) {
        msg("[-] Failed to read encoded configuration data.\n");
        return;
    }

    if (EncodedConfig.size() != len) {
        msg("[-] Encoded configuration size mismatch (expected=%zu, actual=%zu).\n",
            len, EncodedConfig.size());
        return;
    }

    std::string hexdump_raw = formatHexDump(EncodedConfig);
    if (PRINT_DEBUG)
        msg("[+] Encoded raw data:\n%s\n", hexdump_raw.c_str());

    std::vector<uint8_t> decompressedData;
    if (!decode_config_auto(EncodedConfig, len, decompressedData)) {
        msg("[-] Unable to decode ShortLeash configuration with any supported decoder.\n");
        return;
    }

    msg("[+] Decompression and configuration validation succeeded.\n");

    if (PRINT_DEBUG) {
        hexdump_raw = formatHexDump(decompressedData);
        msg("[+] Decompressed Config Data:\n%s\n", hexdump_raw.c_str());
    }

    parse_and_print_shortleash_config(decompressedData);
    return;
}


int pluginMainFunc(void)
{
    // Final exception boundary for malformed/unexpected samples.  Decoder-level
    // errors should already return false, but an unexpected C++ exception must
    // not terminate IDA.
    try {
        ShortLeash_ConfigExtracter();
    }
    catch (const std::exception& e) {
        msg("[-] ShortLeash config extractor exception: %s\n", e.what());
    }
    catch (...) {
        msg("[-] ShortLeash config extractor: unexpected exception.\n");
    }

    return 0;
}


// Define the class that inherits from plugmod_t
class ShortLeash_ConfigExtracter_Plugin : public plugmod_t 
{
public:
    // Constructor
    ShortLeash_ConfigExtracter_Plugin() 
    {
        msg("[+] ShortLeash_ConfigExtracter: Constructor called.\n");
    }

    // Destructor
    virtual ~ShortLeash_ConfigExtracter_Plugin() 
    {
        msg("[+] ShortLeash_ConfigExtracter: Destructor called.\n");
    }

    // Method that gets called when the plugin is activated
    virtual bool idaapi run(size_t arg) override
    {
        msg("[+] ShortLeash_ConfigExtracter.run() called with arg: %d\n", arg);

        pluginMainFunc();

        return true;
    }
};


static plugmod_t* idaapi init(void)
{
    return new ShortLeash_ConfigExtracter_Plugin();
}


#if defined(_WIN32) || defined(_WIN64)
__declspec(dllexport)
#endif
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,         // plugin flags
    init,                 // initialize
    nullptr,              // terminate. this pointer can be nullptr
    nullptr,              // invoke the pluginida
    nullptr,              // long comment about the plugin
    nullptr,              // multiline help about the plugin
    "ShortLeash_ConfigExtracter_Plugin",	  // the preferred short name of the plugin
    ""			  // the preferred hotkey to run the plugin
};