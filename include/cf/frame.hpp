// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Wire framing.
//
// A stream socket carries no message boundaries, so every message is framed:
//
//   offset  size  field
//   0       4     magic 'CFRM' (0x4D524643, little endian on the wire)
//   4       2     wire format version
//   6       2     message type
//   8       2     flags
//   10      2     reserved (must be zero)
//   12      4     payload length
//   16      4     CRC32C over bytes [0, 16)
//   20      4     CRC32C over the payload (0 when the payload is empty)
//
// The header checksum lets the decoder reject a desynchronized stream before it
// trusts the declared payload length. The payload checksum catches corruption
// that survives the transport. Neither is authentication: authenticity comes
// from the HMAC handshake in cf/protocol.hpp.
//
// Every length is bounded twice: by the absolute protocol ceiling and by the
// value the peers negotiated during the handshake. A frame that declares more
// than the negotiated maximum is rejected without allocating.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "cf/result.hpp"

namespace cf {

inline constexpr std::uint32_t kFrameMagic = 0x4D524643u;  // 'CFRM'
inline constexpr std::uint16_t kWireVersion = 1;
inline constexpr std::size_t kFrameHeaderBytes = 24;
/// Protocol ceiling. No configuration may raise it; negotiation may only lower
/// the effective value.
inline constexpr std::uint32_t kAbsoluteMaxPayloadBytes = 16u * 1024u * 1024u;
inline constexpr std::uint32_t kDefaultMaxPayloadBytes = 1u * 1024u * 1024u;
/// Every legal flag bit. Unknown bits are a protocol violation.
inline constexpr std::uint16_t kFrameFlagResponse = 0x0001u;
inline constexpr std::uint16_t kFrameFlagError = 0x0002u;
inline constexpr std::uint16_t kFrameFlagKnownMask = 0x0003u;

/// Wire message types. Numeric values are part of the protocol contract and are
/// never renumbered; new messages take new numbers.
enum class FrameType : std::uint16_t {
  Invalid = 0,

  // Session establishment (10-29)
  Hello = 10,
  HelloAck = 11,
  HelloConfirm = 12,
  AuthReject = 13,

  // Delivery (30-79)
  Prepare = 30,
  PrepareAck = 31,
  PrepareReject = 32,
  Chunk = 33,
  ChunkAck = 34,
  TransferComplete = 35,
  TransferResult = 36,
  Stage = 37,
  StageAck = 38,
  ApplyPrepare = 39,
  ApplyPrepareAck = 40,
  ApplyCommit = 41,
  ApplyCommitAck = 42,
  ApplyAbort = 43,
  ApplyAbortAck = 44,

  // Evidence (80-99)
  DeliveryAck = 80,
  DeliveryNack = 81,

  // Reconciliation (100-119)
  ReconcileRequest = 100,
  ReconcileReport = 101,

  // Control (120-139)
  Retire = 120,
  RetireAck = 121,
  Ping = 122,
  Pong = 123,

  // Teardown (140-149)
  Goodbye = 140,
  Error = 141,

  // Inspection control channel (150-169). Distinct from the agent protocol so
  // that a control client can never be mistaken for a target.
  ControlHello = 150,
  ControlHelloAck = 151,
  ControlRequest = 152,
  ControlResponse = 153,
};

[[nodiscard]] std::string_view frameTypeName(FrameType type) noexcept;
[[nodiscard]] bool parseFrameType(std::string_view text, FrameType& out) noexcept;
/// True when the type is a defined message in this protocol version.
[[nodiscard]] bool isKnownFrameType(FrameType type) noexcept;

struct FrameHeader {
  std::uint16_t wireVersion{kWireVersion};
  FrameType type{FrameType::Invalid};
  std::uint16_t flags{0};
  std::uint16_t reserved{0};
  std::uint32_t payloadLength{0};
  std::uint32_t headerCrc{0};
  std::uint32_t payloadCrc{0};

  friend bool operator==(const FrameHeader&, const FrameHeader&) noexcept = default;
};

/// Encodes exactly the 24 header bytes.
[[nodiscard]] std::vector<std::uint8_t> encodeFrameHeader(const FrameHeader& header);
/// Validates magic, version, flags, reserved bits and the declared length against
/// maxPayloadBytes. Returns the parsed header.
[[nodiscard]] Result<FrameHeader> decodeFrameHeader(std::span<const std::uint8_t> bytes,
                                                    std::uint32_t maxPayloadBytes);

struct Frame {
  FrameHeader header;
  std::vector<std::uint8_t> payload;

  [[nodiscard]] FrameType type() const noexcept { return header.type; }
  [[nodiscard]] bool isResponse() const noexcept {
    return (header.flags & kFrameFlagResponse) != 0;
  }
};

/// Serializes one complete frame. Fails with OversizePayload when the payload
/// exceeds maxPayloadBytes.
[[nodiscard]] Result<std::vector<std::uint8_t>> encodeFrame(FrameType type, std::uint16_t flags,
                                                            std::span<const std::uint8_t> payload,
                                                            std::uint32_t maxPayloadBytes);

/// Incremental stream decoder. Bytes are appended with feed(); complete frames
/// come out in order. A partial frame at the end of a stream is a defect the
/// caller must report: finish() fails rather than silently dropping bytes.
class FrameDecoder final {
 public:
  explicit FrameDecoder(std::uint32_t maxPayloadBytes) noexcept
      : maxPayloadBytes_(maxPayloadBytes) {}

  [[nodiscard]] Status feed(std::span<const std::uint8_t> data, std::vector<Frame>& out);
  [[nodiscard]] Status finish(std::string_view what) const;
  void reset() noexcept {
    buffer_.clear();
    offset_ = 0;
  }

  [[nodiscard]] std::size_t buffered() const noexcept { return buffer_.size() - offset_; }
  [[nodiscard]] std::uint32_t maxPayloadBytes() const noexcept { return maxPayloadBytes_; }

 private:
  std::uint32_t maxPayloadBytes_;
  std::vector<std::uint8_t> buffer_;
  std::size_t offset_{0};
};

}  // namespace cf
