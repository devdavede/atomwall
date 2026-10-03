#include "auth/webauthn/cbor_reader.hpp"

#include <cbor.h>
#include <climits>
#include <cstdlib>
#include <mutex>
#include <stdexcept>

namespace atomwall {

namespace {

// WebAuthn's CBOR structures (attestationObject, COSE keys, assertion
// authenticatorData) are all a few hundred bytes to a couple KB in real use.
// These caps are deliberately generous for that legitimate traffic while
// bounding the cost of hostile input. Capping the input size does NOT bound
// libcbor's allocations: it pre-allocates (and zero-fills) container storage
// from a declared length *before* validating that length against what's
// actually in the buffer, so a 5-byte "array of 2^28 elements" header asks
// for 2 GiB. The allocator cap below is what bounds that; the caps on input
// size and on the size/depth of what we walk afterward are separate,
// deliberately redundant layers of the same "never trust a client-supplied
// length" rule.
constexpr std::size_t kMaxCborBytes = 4096;
constexpr int kMaxDepth = 8;
constexpr std::size_t kMaxContainerElements = 64;

// Far above anything a <= 4096-byte input legitimately needs (64 array slots
// is 512 bytes, a byte string at most 4096), far below a hostile declared
// length. Beyond this libcbor gets NULL and fails the load with
// CBOR_ERR_MEMERROR, as its own docs prescribe for this exact case.
constexpr std::size_t kMaxCborAllocationBytes = 64 * 1024;

void* capped_malloc(std::size_t size) {
    return size > kMaxCborAllocationBytes ? nullptr : std::malloc(size);
}

void* capped_realloc(void* ptr, std::size_t size) {
    return size > kMaxCborAllocationBytes ? nullptr : std::realloc(ptr, size);
}

void install_capped_allocator_once() {
    static std::once_flag installed;
    std::call_once(installed, [] { cbor_set_allocs(capped_malloc, capped_realloc, std::free); });
}

// libcbor's cbor_get_uint64() asserts the item was actually encoded at
// 64-bit width — it does not widen a smaller encoding for you. Canonical/
// minimal CBOR (what every real encoder, including every WebAuthn
// authenticator, produces) always uses the smallest width that fits a given
// value, so small integers like COSE's kty=2 or alg=-7 are 8-bit-encoded —
// calling cbor_get_uint64() directly on those aborts the process via
// libcbor's internal assert. This dispatches on the item's actual width
// first, exactly as libcbor's own docs require.
std::uint64_t get_uint_any_width(cbor_item_t* item) {
    switch (cbor_int_get_width(item)) {
        case CBOR_INT_8:
            return cbor_get_uint8(item);
        case CBOR_INT_16:
            return cbor_get_uint16(item);
        case CBOR_INT_32:
            return cbor_get_uint32(item);
        case CBOR_INT_64:
            return cbor_get_uint64(item);
    }
    throw std::invalid_argument("CBOR integer has an unrecognized width");
}

struct CborItemRef {
    cbor_item_t* item;
    explicit CborItemRef(cbor_item_t* i) : item(i) {}
    ~CborItemRef() {
        if (item) {
            cbor_decref(&item);
        }
    }
    CborItemRef(const CborItemRef&) = delete;
    CborItemRef& operator=(const CborItemRef&) = delete;
};

CborValue convert(cbor_item_t* item, int depth) {
    if (depth > kMaxDepth) {
        throw std::invalid_argument("CBOR nesting too deep");
    }

    CborValue out;
    switch (cbor_typeof(item)) {
        case CBOR_TYPE_UINT:
            out.kind = CborValue::Kind::Uint;
            out.uint_value = get_uint_any_width(item);
            break;
        case CBOR_TYPE_NEGINT:
            out.kind = CborValue::Kind::Negint;
            out.uint_value = get_uint_any_width(item); // raw magnitude N; logical value is -1-N
            break;
        case CBOR_TYPE_BYTESTRING: {
            if (!cbor_bytestring_is_definite(item)) {
                throw std::invalid_argument("indefinite-length CBOR byte strings are not supported");
            }
            out.kind = CborValue::Kind::Bytes;
            const auto len = cbor_bytestring_length(item);
            const auto* handle = cbor_bytestring_handle(item);
            out.bytes.assign(handle, handle + len);
            break;
        }
        case CBOR_TYPE_STRING: {
            if (!cbor_string_is_definite(item)) {
                throw std::invalid_argument("indefinite-length CBOR text strings are not supported");
            }
            out.kind = CborValue::Kind::Text;
            const auto len = cbor_string_length(item);
            const auto* handle = cbor_string_handle(item);
            out.text.assign(reinterpret_cast<const char*>(handle), len);
            break;
        }
        case CBOR_TYPE_ARRAY: {
            const auto count = cbor_array_size(item);
            if (count > kMaxContainerElements) {
                throw std::invalid_argument("CBOR array too large");
            }
            out.kind = CborValue::Kind::Array;
            out.array.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                cbor_item_t* child = cbor_array_get(item, i); // new reference
                if (!child) {
                    throw std::invalid_argument("malformed CBOR array");
                }
                CborItemRef guard(child);
                out.array.push_back(convert(child, depth + 1));
            }
            break;
        }
        case CBOR_TYPE_MAP: {
            const auto count = cbor_map_size(item);
            if (count > kMaxContainerElements) {
                throw std::invalid_argument("CBOR map too large");
            }
            out.kind = CborValue::Kind::Map;
            // cbor_map_handle returns direct pointers into the map's own
            // storage (unlike cbor_array_get, these are borrowed — no
            // incref happened, so they must NOT be decref'd here).
            struct cbor_pair* pairs = cbor_map_handle(item);
            out.map.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                out.map.emplace_back(convert(pairs[i].key, depth + 1),
                                      convert(pairs[i].value, depth + 1));
            }
            break;
        }
        case CBOR_TYPE_FLOAT_CTRL:
            if (cbor_is_bool(item)) {
                out.kind = CborValue::Kind::Bool;
                out.bool_value = cbor_get_bool(item);
            } else if (cbor_is_null(item) || cbor_is_undef(item)) {
                out.kind = CborValue::Kind::Null;
            } else {
                out.kind = CborValue::Kind::Other; // floats: unused by any WebAuthn structure we parse
            }
            break;
        default:
            out.kind = CborValue::Kind::Other;
            break;
    }
    return out;
}

} // namespace

std::pair<CborValue, std::size_t> parse_cbor_prefix(const std::vector<std::uint8_t>& data) {
    if (data.empty() || data.size() > kMaxCborBytes) {
        throw std::invalid_argument("CBOR input is empty or exceeds the size limit");
    }

    install_capped_allocator_once();
    struct cbor_load_result result {};
    cbor_item_t* root = cbor_load(data.data(), data.size(), &result);
    if (!root || result.error.code != CBOR_ERR_NONE) {
        if (root) {
            cbor_decref(&root);
        }
        throw std::invalid_argument("malformed CBOR input");
    }
    CborItemRef guard(root);
    return {convert(root, 0), result.read};
}

CborValue parse_cbor(const std::vector<std::uint8_t>& data) {
    return parse_cbor_prefix(data).first;
}

std::int64_t cbor_to_int64(const CborValue& value) {
    if (value.kind == CborValue::Kind::Uint) {
        if (value.uint_value > static_cast<std::uint64_t>(INT64_MAX)) {
            throw std::invalid_argument("CBOR unsigned integer out of int64 range");
        }
        return static_cast<std::int64_t>(value.uint_value);
    }
    if (value.kind == CborValue::Kind::Negint) {
        if (value.uint_value > static_cast<std::uint64_t>(INT64_MAX)) {
            throw std::invalid_argument("CBOR negative integer out of int64 range");
        }
        return -1 - static_cast<std::int64_t>(value.uint_value);
    }
    throw std::invalid_argument("CBOR value is not an integer");
}

const CborValue* cbor_map_find_int(const CborValue& map, std::int64_t key) {
    if (map.kind != CborValue::Kind::Map) {
        return nullptr;
    }
    for (const auto& [k, v] : map.map) {
        if ((k.kind == CborValue::Kind::Uint || k.kind == CborValue::Kind::Negint) &&
            cbor_to_int64(k) == key) {
            return &v;
        }
    }
    return nullptr;
}

const CborValue* cbor_map_find_text(const CborValue& map, std::string_view key) {
    if (map.kind != CborValue::Kind::Map) {
        return nullptr;
    }
    for (const auto& [k, v] : map.map) {
        if (k.kind == CborValue::Kind::Text && k.text == key) {
            return &v;
        }
    }
    return nullptr;
}

} // namespace atomwall
