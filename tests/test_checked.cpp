// Unit and property tests: checked arithmetic and bounded decoding.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <limits>
#include <vector>

#include "cf/checked.hpp"
#include "cf/codec.hpp"
#include "cf/rng.hpp"
#include "testing.hpp"

CF_TEST(unit, checked_add_sub_mul) {
  CF_EXPECT_EQ(*cf::checkedAdd<std::uint32_t>(1u, 2u), 3u);
  CF_EXPECT(!cf::checkedAdd<std::uint32_t>(0xFFFFFFFFu, 1u).has_value());
  CF_EXPECT_EQ(*cf::checkedSub<std::uint32_t>(3u, 2u), 1u);
  CF_EXPECT(!cf::checkedSub<std::uint32_t>(2u, 3u).has_value());
  CF_EXPECT_EQ(*cf::checkedMul<std::uint32_t>(3u, 4u), 12u);
  CF_EXPECT(!cf::checkedMul<std::uint32_t>(0x80000000u, 2u).has_value());
  CF_EXPECT_EQ(*cf::checkedMul<std::uint32_t>(0u, 0xFFFFFFFFu), 0u);
}

CF_TEST(unit, checked_cast_rejects_truncation) {
  CF_EXPECT_EQ(*cf::checkedCast<std::uint8_t>(255u), static_cast<std::uint8_t>(255));
  CF_EXPECT(!cf::checkedCast<std::uint8_t>(256u).has_value());
  CF_EXPECT(!cf::checkedCast<std::uint32_t>(-1).has_value());
  CF_EXPECT_EQ(*cf::checkedCast<std::int32_t>(7), 7);
  CF_EXPECT(!cf::checkedCast<std::int32_t>(std::numeric_limits<std::int64_t>::max()).has_value());
}

CF_TEST(unit, saturating_sub) {
  CF_EXPECT_EQ(cf::saturatingSub<std::uint32_t>(5u, 3u), 2u);
  CF_EXPECT_EQ(cf::saturatingSub<std::uint32_t>(3u, 5u), 0u);
}

CF_TEST(unit, byte_round_trip) {
  cf::ByteWriter writer;
  writer.u8(0x12);
  writer.boolean(true);
  writer.u16(0xBEEF);
  writer.u32(0xDEADBEEF);
  writer.u64(0x0123456789ABCDEFull);
  writer.i64(-123456789);
  writer.string("hello", 32);
  writer.digest(cf::Digest::ofText("payload"));

  cf::ByteReader reader(writer.span());
  CF_EXPECT_EQ(reader.u8().value(), static_cast<std::uint8_t>(0x12));
  CF_EXPECT_EQ(reader.boolean().value(), true);
  CF_EXPECT_EQ(reader.u16().value(), static_cast<std::uint16_t>(0xBEEF));
  CF_EXPECT_EQ(reader.u32().value(), 0xDEADBEEFu);
  CF_EXPECT_EQ(reader.u64().value(), 0x0123456789ABCDEFull);
  CF_EXPECT_EQ(reader.i64().value(), static_cast<std::int64_t>(-123456789));
  const auto text = reader.string(32);
  CF_REQUIRE_OK(text);
  CF_EXPECT_EQ(text.value(), std::string("hello"));
  const auto digest = reader.digest();
  CF_REQUIRE_OK(digest);
  CF_EXPECT_EQ(digest.value(), cf::Digest::ofText("payload"));
  CF_EXPECT_OK(reader.requireEnd());
}

CF_TEST(adversarial, decoder_rejects_truncation_and_oversize) {
  cf::ByteWriter writer;
  writer.u32(0xDEADBEEFu);
  writer.string("abcdef", 32);
  const std::vector<std::uint8_t> encoded = writer.take();

  // Every truncation length must fail rather than read past the end.
  for (std::size_t length = 0; length < encoded.size(); ++length) {
    cf::ByteReader reader(std::span<const std::uint8_t>(encoded.data(), length));
    const auto value = reader.u32();
    if (length < 4) {
      CF_EXPECT_CODE(value, cf::ErrorCode::TruncatedFrame);
      continue;
    }
    CF_EXPECT_OK(value);
    const auto text = reader.string(32);
    CF_EXPECT(!text.hasValue());
  }

  // A declared length beyond the caller's bound is refused without allocating.
  cf::ByteWriter hostile;
  hostile.u32(0xFFFFFFFFu);
  cf::ByteReader reader(hostile.span());
  const auto text = reader.string(64);
  CF_EXPECT_CODE(text, cf::ErrorCode::OversizePayload);
}

CF_TEST(adversarial, decoder_rejects_trailing_bytes) {
  cf::ByteWriter writer;
  writer.u8(1);
  writer.u8(2);
  cf::ByteReader reader(writer.span());
  CF_EXPECT_OK(reader.u8());
  CF_EXPECT_CODE(reader.requireEnd(), cf::ErrorCode::ProtocolViolation);
}

CF_TEST(property, round_trip_random_values) {
  cf::Rng rng(cftest::runSeed() ^ 0xA5A5A5A5ull);
  for (int iteration = 0; iteration < 200; ++iteration) {
    const std::uint64_t a = rng.next();
    const std::uint64_t b = rng.next();
    const std::string text = "id-" + std::to_string(a % 100000) + "-" + std::to_string(b % 97);

    cf::ByteWriter writer;
    writer.u64(a);
    writer.u64(b);
    writer.string(text, 256);

    cf::ByteReader reader(writer.span());
    const auto readA = reader.u64();
    const auto readB = reader.u64();
    const auto readText = reader.string(256);
    CF_EXPECT_OK(readA);
    CF_EXPECT_OK(readB);
    CF_EXPECT_OK(readText);
    CF_EXPECT_EQ(readA.value(), a);
    CF_EXPECT_EQ(readB.value(), b);
    CF_EXPECT_EQ(readText.value(), text);
    CF_EXPECT_OK(reader.requireEnd());
  }
}
