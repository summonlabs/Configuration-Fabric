// Unit, adversarial and property tests: wire framing.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <string>
#include <vector>

#include "cf/frame.hpp"
#include "cf/rng.hpp"
#include "testing.hpp"

namespace {

std::vector<std::uint8_t> bytesOf(std::string_view text) {
  return std::vector<std::uint8_t>(text.begin(), text.end());
}

}  // namespace

CF_TEST(unit, encode_decode_round_trip) {
  const std::vector<std::uint8_t> payload = bytesOf("hello frame");
  auto encoded = cf::encodeFrame(cf::FrameType::Hello, 0, payload, cf::kDefaultMaxPayloadBytes);
  CF_EXPECT_OK(encoded);
  CF_EXPECT_EQ(encoded.value().size(), cf::kFrameHeaderBytes + payload.size());

  cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
  std::vector<cf::Frame> frames;
  CF_EXPECT_OK(decoder.feed(encoded.value(), frames));
  CF_EXPECT_EQ(frames.size(), std::size_t{1});
  CF_EXPECT_EQ(frames[0].type(), cf::FrameType::Hello);
  CF_EXPECT(frames[0].payload == payload);
  CF_EXPECT_OK(decoder.finish("test"));
}

CF_TEST(unit, empty_payload_round_trip) {
  auto encoded = cf::encodeFrame(cf::FrameType::Ping, cf::kFrameFlagResponse,
                                 std::span<const std::uint8_t>(), cf::kDefaultMaxPayloadBytes);
  CF_EXPECT_OK(encoded);
  cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
  std::vector<cf::Frame> frames;
  CF_EXPECT_OK(decoder.feed(encoded.value(), frames));
  CF_EXPECT_EQ(frames.size(), std::size_t{1});
  CF_EXPECT(frames[0].payload.empty());
  CF_EXPECT(frames[0].isResponse());
}

CF_TEST(unit, byte_at_a_time_decoding_is_equivalent) {
  const std::vector<std::uint8_t> payload = bytesOf("streamed");
  auto encoded = cf::encodeFrame(cf::FrameType::Chunk, 0, payload, cf::kDefaultMaxPayloadBytes);
  CF_EXPECT_OK(encoded);
  cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
  std::vector<cf::Frame> frames;
  for (const std::uint8_t byte : encoded.value()) {
    CF_EXPECT_OK(decoder.feed(std::span<const std::uint8_t>(&byte, 1), frames));
  }
  CF_EXPECT_EQ(frames.size(), std::size_t{1});
  CF_EXPECT(frames[0].payload == payload);
}

CF_TEST(unit, pipelined_frames_in_one_read) {
  std::vector<std::uint8_t> stream;
  for (int i = 0; i < 8; ++i) {
    const std::vector<std::uint8_t> payload = bytesOf("frame-" + std::to_string(i));
    auto encoded = cf::encodeFrame(cf::FrameType::ChunkAck, 0, payload, cf::kDefaultMaxPayloadBytes);
    CF_EXPECT_OK(encoded);
    stream.insert(stream.end(), encoded.value().begin(), encoded.value().end());
  }
  cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
  std::vector<cf::Frame> frames;
  CF_EXPECT_OK(decoder.feed(stream, frames));
  CF_EXPECT_EQ(frames.size(), std::size_t{8});
}

CF_TEST(adversarial, truncated_stream_is_reported_not_dropped) {
  const std::vector<std::uint8_t> payload = bytesOf("payload that will be cut short");
  auto encoded = cf::encodeFrame(cf::FrameType::Prepare, 0, payload, cf::kDefaultMaxPayloadBytes);
  CF_EXPECT_OK(encoded);
  for (std::size_t length = 1; length < encoded.value().size(); ++length) {
    cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
    std::vector<cf::Frame> frames;
    const cf::Status fed =
        decoder.feed(std::span<const std::uint8_t>(encoded.value().data(), length), frames);
    if (!fed) {
      continue;
    }
    if (frames.empty()) {
      CF_EXPECT(!decoder.finish("truncated"));
    } else {
      CF_EXPECT_OK(decoder.finish("truncated"));
    }
  }
}

CF_TEST(adversarial, corrupt_header_and_payload_are_rejected) {
  const std::vector<std::uint8_t> payload = bytesOf("checksum me");
  auto encoded = cf::encodeFrame(cf::FrameType::Stage, 0, payload, cf::kDefaultMaxPayloadBytes);
  CF_EXPECT_OK(encoded);

  for (std::size_t i = 0; i < cf::kFrameHeaderBytes; ++i) {
    std::vector<std::uint8_t> damaged = encoded.value();
    damaged[i] = static_cast<std::uint8_t>(damaged[i] ^ 0x01u);
    cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
    std::vector<cf::Frame> frames;
    const cf::Status fed = decoder.feed(damaged, frames);
    CF_EXPECT(!fed || frames.empty());
  }
  for (std::size_t i = cf::kFrameHeaderBytes; i < encoded.value().size(); ++i) {
    std::vector<std::uint8_t> damaged = encoded.value();
    damaged[i] = static_cast<std::uint8_t>(damaged[i] ^ 0x01u);
    cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
    std::vector<cf::Frame> frames;
    CF_EXPECT_CODE(decoder.feed(damaged, frames), cf::ErrorCode::IntegrityFailure);
  }
}

CF_TEST(adversarial, oversize_declaration_is_refused_without_allocation) {
  // A hostile header that declares a 4 GiB payload against a 1 MiB ceiling.
  auto encoded = cf::encodeFrame(cf::FrameType::Chunk, 0, bytesOf("tiny"),
                                 cf::kDefaultMaxPayloadBytes);
  CF_EXPECT_OK(encoded);
  std::vector<std::uint8_t> hostile = encoded.value();
  const std::uint32_t huge = 0xFFFFFFFFu;
  for (unsigned i = 0; i < 4; ++i) {
    hostile[12 + i] = static_cast<std::uint8_t>((huge >> (i * 8)) & 0xFFu);
  }
  // Repair the header checksum so the length field itself is the only anomaly.
  const std::uint32_t headerCrc =
      cf::crc32c(std::span<const std::uint8_t>(hostile.data(), 16));
  for (unsigned i = 0; i < 4; ++i) {
    hostile[16 + i] = static_cast<std::uint8_t>((headerCrc >> (i * 8)) & 0xFFu);
  }
  cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
  std::vector<cf::Frame> frames;
  CF_EXPECT_CODE(decoder.feed(hostile, frames), cf::ErrorCode::OversizePayload);
  CF_EXPECT(frames.empty());
}

CF_TEST(adversarial, unknown_flags_reserved_and_types_are_refused) {
  auto encoded = cf::encodeFrame(cf::FrameType::Ping, 0, std::span<const std::uint8_t>(),
                                 cf::kDefaultMaxPayloadBytes);
  CF_EXPECT_OK(encoded);

  std::vector<std::uint8_t> badFlags = encoded.value();
  badFlags[8] = 0x80;
  const std::uint32_t flagsCrc = cf::crc32c(std::span<const std::uint8_t>(badFlags.data(), 16));
  for (unsigned i = 0; i < 4; ++i) {
    badFlags[16 + i] = static_cast<std::uint8_t>((flagsCrc >> (i * 8)) & 0xFFu);
  }
  {
    cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
    std::vector<cf::Frame> frames;
    CF_EXPECT(!decoder.feed(badFlags, frames));
  }

  std::vector<std::uint8_t> badReserved = encoded.value();
  badReserved[10] = 0x01;
  const std::uint32_t reservedCrc =
      cf::crc32c(std::span<const std::uint8_t>(badReserved.data(), 16));
  for (unsigned i = 0; i < 4; ++i) {
    badReserved[16 + i] = static_cast<std::uint8_t>((reservedCrc >> (i * 8)) & 0xFFu);
  }
  {
    cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
    std::vector<cf::Frame> frames;
    CF_EXPECT(!decoder.feed(badReserved, frames));
  }

  std::vector<std::uint8_t> badType = encoded.value();
  badType[6] = 0xEE;
  badType[7] = 0xEE;
  const std::uint32_t typeCrc = cf::crc32c(std::span<const std::uint8_t>(badType.data(), 16));
  for (unsigned i = 0; i < 4; ++i) {
    badType[16 + i] = static_cast<std::uint8_t>((typeCrc >> (i * 8)) & 0xFFu);
  }
  {
    cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
    std::vector<cf::Frame> frames;
    CF_EXPECT_CODE(decoder.feed(badType, frames), cf::ErrorCode::UnexpectedMessage);
  }
}

CF_TEST(adversarial, magic_mismatch_is_a_protocol_violation) {
  auto encoded = cf::encodeFrame(cf::FrameType::Ping, 0, std::span<const std::uint8_t>(),
                                 cf::kDefaultMaxPayloadBytes);
  CF_EXPECT_OK(encoded);
  std::vector<std::uint8_t> hostile = encoded.value();
  hostile[0] = 0x00;
  const std::uint32_t crc = cf::crc32c(std::span<const std::uint8_t>(hostile.data(), 16));
  for (unsigned i = 0; i < 4; ++i) {
    hostile[16 + i] = static_cast<std::uint8_t>((crc >> (i * 8)) & 0xFFu);
  }
  cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
  std::vector<cf::Frame> frames;
  CF_EXPECT_CODE(decoder.feed(hostile, frames), cf::ErrorCode::ProtocolViolation);
}

CF_TEST(unit, frame_type_names_round_trip) {
  for (std::uint16_t raw = 1; raw <= 153; ++raw) {
    const auto type = static_cast<cf::FrameType>(raw);
    const std::string_view name = cf::frameTypeName(type);
    if (name == "unknown") {
      CF_EXPECT(!cf::isKnownFrameType(type));
      continue;
    }
    CF_EXPECT(cf::isKnownFrameType(type));
    cf::FrameType parsed{};
    CF_EXPECT(cf::parseFrameType(name, parsed));
    CF_EXPECT(parsed == type);
  }
}

CF_TEST(property, random_payload_framing_round_trip) {
  cf::Rng rng(cftest::runSeed() ^ 0xF00Du);
  for (int iteration = 0; iteration < 300; ++iteration) {
    const std::size_t length = static_cast<std::size_t>(rng.bounded(4096));
    std::vector<std::uint8_t> payload(length);
    rng.fillBytes(std::span<std::uint8_t>(payload.data(), payload.size()));
    const auto type = static_cast<cf::FrameType>(1 + rng.bounded(153));
    if (!cf::isKnownFrameType(type)) {
      continue;
    }
    const std::uint16_t flags = static_cast<std::uint16_t>(rng.bounded(4));
    auto encoded = cf::encodeFrame(type, flags, payload, cf::kDefaultMaxPayloadBytes);
    CF_EXPECT_OK(encoded);
    cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
    std::vector<cf::Frame> frames;
    // Feed in random-sized pieces to exercise buffer compaction.
    std::size_t offset = 0;
    while (offset < encoded.value().size()) {
      const std::size_t take =
          std::min<std::size_t>(encoded.value().size() - offset, 1 + rng.bounded(97));
      CF_EXPECT_OK(decoder.feed(
          std::span<const std::uint8_t>(encoded.value().data() + offset, take), frames));
      offset += take;
    }
    CF_EXPECT_EQ(frames.size(), std::size_t{1});
    if (!frames.empty()) {
      CF_EXPECT(frames[0].payload == payload);
      CF_EXPECT(frames[0].header.flags == flags);
      CF_EXPECT(frames[0].type() == type);
    }
  }
}
