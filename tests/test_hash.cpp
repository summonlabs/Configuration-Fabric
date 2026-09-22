// Unit tests: hashing, HMAC, CRC32C and hex conversion against known vectors.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <string>

#include "cf/hash.hpp"
#include "cf/rng.hpp"
#include "testing.hpp"

namespace {


std::string hexOf(const cf::Sha256Digest& digest) {
  return cf::toHex(std::span<const std::uint8_t>(digest.data(), digest.size()));
}

}  // namespace

CF_TEST(unit, sha256_known_vectors) {
  // FIPS 180-4 / NIST examples.
  CF_EXPECT_EQ(hexOf(cf::sha256(std::string_view(""))),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  CF_EXPECT_EQ(hexOf(cf::sha256(std::string_view("abc"))),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  CF_EXPECT_EQ(
      hexOf(cf::sha256(std::string_view(
          "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
      std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  // The 1,000,000 'a' vector.
  std::string million(1000000, 'a');
  CF_EXPECT_EQ(hexOf(cf::sha256(million)),
               std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

CF_TEST(unit, sha256_streaming_matches_oneshot) {
  // Every boundary around the 64-byte block, including the padding edge at 55/56.
  for (std::size_t length = 0; length <= 200; ++length) {
    std::string text;
    text.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
      text.push_back(static_cast<char>('a' + (i % 26)));
    }
    const cf::Sha256Digest oneShot = cf::sha256(text);
    cf::Sha256 hasher;
    // Feed in awkward pieces to exercise the buffering path.
    std::size_t offset = 0;
    std::size_t piece = 1;
    while (offset < text.size()) {
      const std::size_t take = std::min(piece, text.size() - offset);
      hasher.update(std::string_view(text).substr(offset, take));
      offset += take;
      piece = (piece * 7u) % 61u + 1u;
    }
    CF_EXPECT_EQ(hexOf(hasher.finish()), hexOf(oneShot));
  }
}

CF_TEST(unit, hmac_sha256_rfc4231_vectors) {
  const auto hmac = [](std::span<const std::uint8_t> key, std::string_view message) {
    return hexOf(cf::hmacSha256(key, message));
  };
  const auto repeated = [](std::size_t count, std::uint8_t value) {
    return std::vector<std::uint8_t>(count, value);
  };

  // RFC 4231 test case 1: 20-byte key.
  const std::vector<std::uint8_t> key1 = repeated(20, 0x0b);
  CF_EXPECT_EQ(hmac(key1, "Hi There"),
               std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));

  // RFC 4231 test case 2: short key.
  const std::string jefeText = "Jefe";
  const std::vector<std::uint8_t> key2(jefeText.begin(), jefeText.end());
  CF_EXPECT_EQ(hmac(key2, "what do ya want for nothing?"),
               std::string("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));

  // RFC 4231 test case 3.
  const std::vector<std::uint8_t> key3 = repeated(20, 0xaa);
  const std::vector<std::uint8_t> data3 = repeated(50, 0xdd);
  CF_EXPECT_EQ(hexOf(cf::hmacSha256(key3, data3)),
               std::string("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"));

  // RFC 4231 test case 4: 25-byte key.
  std::vector<std::uint8_t> key4(25);
  for (std::size_t i = 0; i < key4.size(); ++i) {
    key4[i] = static_cast<std::uint8_t>(i + 1);
  }
  const std::vector<std::uint8_t> data4 = repeated(50, 0xcd);
  CF_EXPECT_EQ(hexOf(cf::hmacSha256(key4, data4)),
               std::string("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"));

  // RFC 4231 test case 6: a key longer than the block size must be hashed first.
  const std::vector<std::uint8_t> key6 = repeated(131, 0xaa);
  CF_EXPECT_EQ(hmac(key6, "Test Using Larger Than Block-Size Key - Hash Key First"),
               std::string("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));

  // RFC 4231 test case 7: long key and long message.
  CF_EXPECT_EQ(
      hmac(key6,
           "This is a test using a larger than block-size key and a larger than block-size "
           "data. The key needs to be hashed before being used by the HMAC algorithm."),
      std::string("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"));

  // The fixed-width session key path must agree with the general form, because
  // the handshake uses the former.
  cf::HmacKey fixed{};
  for (std::size_t i = 0; i < fixed.size(); ++i) {
    fixed[i] = static_cast<std::uint8_t>(i * 7 + 3);
  }
  CF_EXPECT_EQ(hexOf(cf::hmacSha256(fixed, std::string_view("transcript"))),
               hexOf(cf::hmacSha256(std::span<const std::uint8_t>(fixed.data(), fixed.size()),
                                    "transcript")));
}

CF_TEST(unit, constant_time_equals) {
  const std::array<std::uint8_t, 4> a = {1, 2, 3, 4};
  const std::array<std::uint8_t, 4> b = {1, 2, 3, 4};
  const std::array<std::uint8_t, 4> c = {1, 2, 3, 5};
  const std::array<std::uint8_t, 3> d = {1, 2, 3};
  CF_EXPECT(cf::constantTimeEquals(a, b));
  CF_EXPECT(!cf::constantTimeEquals(a, c));
  CF_EXPECT(!cf::constantTimeEquals(a, d));
}

CF_TEST(unit, crc32c_known_vector) {
  // The CRC32C of "123456789" is the standard check value.
  CF_EXPECT_EQ(cf::crc32c(std::string_view("123456789")), 0xE3069283u);
  CF_EXPECT_EQ(cf::crc32c(std::string_view("")), 0u);
  cf::Crc32c incremental;
  const std::string first = "12345";
  const std::string second = "6789";
  incremental.update(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(first.data()), first.size()));
  incremental.update(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(second.data()), second.size()));
  CF_EXPECT_EQ(incremental.value() ^ 0xFFFFFFFFu, 0xE3069283u);
}

CF_TEST(unit, hex_round_trip_and_rejection) {
  const std::array<std::uint8_t, 4> bytes = {0x00, 0x7F, 0x80, 0xFF};
  const std::string hex = cf::toHex(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
  CF_EXPECT_EQ(hex, std::string("007f80ff"));
  std::array<std::uint8_t, 4> restored{};
  CF_EXPECT(cf::fromHex(hex, std::span<std::uint8_t>(restored.data(), restored.size())));
  CF_EXPECT(restored == bytes);
  CF_EXPECT(!cf::fromHex("007f80f", std::span<std::uint8_t>(restored.data(), restored.size())));
  CF_EXPECT(!cf::fromHex("007f80fg", std::span<std::uint8_t>(restored.data(), restored.size())));
}

CF_TEST(unit, chacha20_rfc8439_keystream) {
  cf::HmacKey key{};
  for (std::size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<std::uint8_t>(i);
  }
  const std::array<std::uint8_t, 12> nonce = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
                                              0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
  cf::ChaCha20 stream(key, nonce, 1);
  std::array<std::uint8_t, 64> block{};
  stream.keystream(std::span<std::uint8_t>(block.data(), block.size()));
  CF_EXPECT_EQ(cf::toHex(std::span<const std::uint8_t>(block.data(), block.size())),
               std::string("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                           "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"));
  // Advancing the generator continues the same keystream across calls.
  cf::ChaCha20 split(key, nonce, 1);
  std::array<std::uint8_t, 32> first{};
  std::array<std::uint8_t, 32> second{};
  split.keystream(std::span<std::uint8_t>(first.data(), first.size()));
  split.keystream(std::span<std::uint8_t>(second.data(), second.size()));
  CF_EXPECT_EQ(cf::toHex(std::span<const std::uint8_t>(first.data(), first.size())),
               cf::toHex(std::span<const std::uint8_t>(block.data(), 32)));
  CF_EXPECT_EQ(cf::toHex(std::span<const std::uint8_t>(second.data(), second.size())),
               cf::toHex(std::span<const std::uint8_t>(block.data() + 32, 32)));
}

CF_TEST(unit, secure_random_is_not_constant) {
  const std::array<std::uint8_t, 16> first = cf::secureRandom128();
  const std::array<std::uint8_t, 16> second = cf::secureRandom128();
  CF_EXPECT(!(first == second));
  bool anyNonZero = false;
  for (const std::uint8_t byte : first) {
    if (byte != 0) {
      anyNonZero = true;
    }
  }
  CF_EXPECT(anyNonZero);
}
