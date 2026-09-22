// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/frame.hpp"

#include <algorithm>
#include <array>

#include "cf/checked.hpp"
#include "cf/contract.hpp"
#include "cf/hash.hpp"

namespace cf {
namespace {

void storeLe32(std::uint8_t* out, std::uint32_t value) noexcept {
  for (unsigned i = 0; i < 4; ++i) {
    out[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu);
  }
}

void storeLe16(std::uint8_t* out, std::uint16_t value) noexcept {
  out[0] = static_cast<std::uint8_t>(value & 0xFFu);
  out[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
}

[[nodiscard]] std::uint32_t loadLe32(const std::uint8_t* in) noexcept {
  return static_cast<std::uint32_t>(in[0]) | (static_cast<std::uint32_t>(in[1]) << 8) |
         (static_cast<std::uint32_t>(in[2]) << 16) | (static_cast<std::uint32_t>(in[3]) << 24);
}

[[nodiscard]] std::uint16_t loadLe16(const std::uint8_t* in) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(in[0]) |
                                    static_cast<std::uint16_t>(static_cast<std::uint16_t>(in[1])
                                                               << 8));
}

}  // namespace

std::string_view frameTypeName(FrameType type) noexcept {
  switch (type) {
    case FrameType::Invalid:
      return "invalid";
    case FrameType::Hello:
      return "hello";
    case FrameType::HelloAck:
      return "hello-ack";
    case FrameType::HelloConfirm:
      return "hello-confirm";
    case FrameType::AuthReject:
      return "auth-reject";
    case FrameType::Prepare:
      return "prepare";
    case FrameType::PrepareAck:
      return "prepare-ack";
    case FrameType::PrepareReject:
      return "prepare-reject";
    case FrameType::Chunk:
      return "chunk";
    case FrameType::ChunkAck:
      return "chunk-ack";
    case FrameType::TransferComplete:
      return "transfer-complete";
    case FrameType::TransferResult:
      return "transfer-result";
    case FrameType::Stage:
      return "stage";
    case FrameType::StageAck:
      return "stage-ack";
    case FrameType::ApplyPrepare:
      return "apply-prepare";
    case FrameType::ApplyPrepareAck:
      return "apply-prepare-ack";
    case FrameType::ApplyCommit:
      return "apply-commit";
    case FrameType::ApplyCommitAck:
      return "apply-commit-ack";
    case FrameType::ApplyAbort:
      return "apply-abort";
    case FrameType::ApplyAbortAck:
      return "apply-abort-ack";
    case FrameType::DeliveryAck:
      return "delivery-ack";
    case FrameType::DeliveryNack:
      return "delivery-nack";
    case FrameType::ReconcileRequest:
      return "reconcile-request";
    case FrameType::ReconcileReport:
      return "reconcile-report";
    case FrameType::Retire:
      return "retire";
    case FrameType::RetireAck:
      return "retire-ack";
    case FrameType::Ping:
      return "ping";
    case FrameType::Pong:
      return "pong";
    case FrameType::Goodbye:
      return "goodbye";
    case FrameType::Error:
      return "error";
    case FrameType::ControlHello:
      return "control-hello";
    case FrameType::ControlHelloAck:
      return "control-hello-ack";
    case FrameType::ControlRequest:
      return "control-request";
    case FrameType::ControlResponse:
      return "control-response";
  }
  return "unknown";
}

bool parseFrameType(std::string_view text, FrameType& out) noexcept {
  for (std::uint16_t raw = 1; raw <= 153; ++raw) {
    const auto type = static_cast<FrameType>(raw);
    const std::string_view name = frameTypeName(type);
    if (name != "unknown" && name == text) {
      out = type;
      return true;
    }
  }
  return false;
}

bool isKnownFrameType(FrameType type) noexcept { return frameTypeName(type) != "unknown"; }

std::vector<std::uint8_t> encodeFrameHeader(const FrameHeader& header) {
  std::vector<std::uint8_t> bytes(kFrameHeaderBytes, 0);
  storeLe32(bytes.data(), kFrameMagic);
  storeLe16(bytes.data() + 4, header.wireVersion);
  storeLe16(bytes.data() + 6, static_cast<std::uint16_t>(header.type));
  storeLe16(bytes.data() + 8, header.flags);
  storeLe16(bytes.data() + 10, header.reserved);
  storeLe32(bytes.data() + 12, header.payloadLength);
  const std::uint32_t headerCrc =
      crc32c(std::span<const std::uint8_t>(bytes.data(), 16));
  storeLe32(bytes.data() + 16, headerCrc);
  storeLe32(bytes.data() + 20, header.payloadCrc);
  return bytes;
}

Result<FrameHeader> decodeFrameHeader(std::span<const std::uint8_t> bytes,
                                      std::uint32_t maxPayloadBytes) {
  if (bytes.size() < kFrameHeaderBytes) {
    return Result<FrameHeader>::fail(ErrorCode::TruncatedFrame,
                                     "stream ended inside a frame header",
                                     std::to_string(bytes.size()));
  }
  if (maxPayloadBytes > kAbsoluteMaxPayloadBytes) {
    return Result<FrameHeader>::fail(ErrorCode::Internal,
                                     "configured payload ceiling exceeds the protocol ceiling");
  }
  const std::uint32_t magic = loadLe32(bytes.data());
  if (magic != kFrameMagic) {
    return Result<FrameHeader>::fail(ErrorCode::ProtocolViolation,
                                     "frame magic does not match; the stream is not framed by this "
                                     "protocol or it has desynchronized");
  }
  const std::uint32_t expectedHeaderCrc = loadLe32(bytes.data() + 16);
  if (crc32c(bytes.first(16)) != expectedHeaderCrc) {
    return Result<FrameHeader>::fail(ErrorCode::IntegrityFailure,
                                     "frame header checksum does not match");
  }

  FrameHeader header;
  header.wireVersion = loadLe16(bytes.data() + 4);
  if (header.wireVersion != kWireVersion) {
    return Result<FrameHeader>::fail(ErrorCode::UnsupportedVersion,
                                     "frame wire version is not supported",
                                     std::to_string(header.wireVersion));
  }
  header.type = static_cast<FrameType>(loadLe16(bytes.data() + 6));
  if (!isKnownFrameType(header.type)) {
    return Result<FrameHeader>::fail(ErrorCode::UnexpectedMessage,
                                     "frame carries an undefined message type",
                                     std::to_string(static_cast<std::uint16_t>(header.type)));
  }
  header.flags = loadLe16(bytes.data() + 8);
  if ((header.flags & ~kFrameFlagKnownMask) != 0) {
    return Result<FrameHeader>::fail(ErrorCode::ProtocolViolation, "frame carries unknown flag bits",
                                     std::to_string(header.flags));
  }
  header.reserved = loadLe16(bytes.data() + 10);
  if (header.reserved != 0) {
    return Result<FrameHeader>::fail(ErrorCode::ProtocolViolation,
                                     "frame reserved field must be zero");
  }
  header.payloadLength = loadLe32(bytes.data() + 12);
  if (header.payloadLength > maxPayloadBytes) {
    return Result<FrameHeader>::fail(
        ErrorCode::OversizePayload, "frame declares a payload larger than the negotiated maximum",
        std::to_string(header.payloadLength) + " > " + std::to_string(maxPayloadBytes));
  }
  header.payloadCrc = loadLe32(bytes.data() + 20);
  if (header.payloadLength == 0 && header.payloadCrc != 0) {
    return Result<FrameHeader>::fail(ErrorCode::ProtocolViolation,
                                     "empty frame declares a non-zero payload checksum");
  }
  return Result<FrameHeader>::ok(header);
}

Result<std::vector<std::uint8_t>> encodeFrame(FrameType type, std::uint16_t flags,
                                              std::span<const std::uint8_t> payload,
                                              std::uint32_t maxPayloadBytes) {
  if (!isKnownFrameType(type)) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::InvalidArgument,
                                                   "cannot encode an undefined message type");
  }
  if (maxPayloadBytes > kAbsoluteMaxPayloadBytes) {
    return Result<std::vector<std::uint8_t>>::fail(
        ErrorCode::InvalidArgument, "payload ceiling exceeds the protocol ceiling");
  }
  if (payload.size() > maxPayloadBytes) {
    return Result<std::vector<std::uint8_t>>::fail(
        ErrorCode::OversizePayload, "payload exceeds the negotiated maximum",
        std::to_string(payload.size()) + " > " + std::to_string(maxPayloadBytes));
  }
  if ((flags & ~kFrameFlagKnownMask) != 0) {
    return Result<std::vector<std::uint8_t>>::fail(ErrorCode::InvalidArgument,
                                                   "cannot encode unknown flag bits");
  }
  FrameHeader header;
  header.wireVersion = kWireVersion;
  header.type = type;
  header.flags = flags;
  header.reserved = 0;
  header.payloadLength = static_cast<std::uint32_t>(payload.size());
  header.payloadCrc = payload.empty() ? 0u : crc32c(payload);
  const std::vector<std::uint8_t> headerBytes = encodeFrameHeader(header);

  std::vector<std::uint8_t> out;
  out.reserve(headerBytes.size() + payload.size());
  out.insert(out.end(), headerBytes.begin(), headerBytes.end());
  out.insert(out.end(), payload.begin(), payload.end());
  return Result<std::vector<std::uint8_t>>::ok(std::move(out));
}

Status FrameDecoder::feed(std::span<const std::uint8_t> data, std::vector<Frame>& out) {
  if (data.empty()) {
    return Status::ok();
  }
  // Compact before growing so a long-lived connection does not accumulate
  // consumed bytes.
  if (offset_ > 0 && offset_ == buffer_.size()) {
    buffer_.clear();
    offset_ = 0;
  } else if (offset_ > 0 && offset_ > (buffer_.size() / 2)) {
    buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(offset_));
    offset_ = 0;
  }

  const auto ceiling = checkedAdd<std::size_t>(kFrameHeaderBytes, maxPayloadBytes_);
  if (!ceiling) {
    return Status::fail(ErrorCode::Internal, "frame size ceiling overflowed");
  }
  const auto projected = checkedAdd<std::size_t>(buffer_.size(), data.size());
  if (!projected) {
    return Status::fail(ErrorCode::ArithmeticOverflow, "receive buffer size overflowed");
  }
  buffer_.insert(buffer_.end(), data.begin(), data.end());

  for (;;) {
    const std::size_t available = buffer_.size() - offset_;
    if (available < kFrameHeaderBytes) {
      break;
    }
    auto header = decodeFrameHeader(
        std::span<const std::uint8_t>(buffer_.data() + offset_, kFrameHeaderBytes),
        maxPayloadBytes_);
    if (!header) {
      return Status::fail(header.error());
    }
    const std::size_t total = kFrameHeaderBytes + header.value().payloadLength;
    if (available < total) {
      break;
    }
    const std::uint8_t* payloadStart = buffer_.data() + offset_ + kFrameHeaderBytes;
    const std::span<const std::uint8_t> payload(payloadStart, header.value().payloadLength);
    if (!payload.empty() && crc32c(payload) != header.value().payloadCrc) {
      return Status::fail(ErrorCode::IntegrityFailure,
                          "frame payload checksum does not match",
                          std::string(frameTypeName(header.value().type)));
    }
    Frame frame;
    frame.header = header.value();
    frame.payload.assign(payload.begin(), payload.end());
    out.push_back(std::move(frame));
    offset_ += total;
  }
  // After every complete frame has been consumed the remainder is at most one
  // partially received frame, which decodeFrameHeader has already proven cannot
  // exceed the negotiated ceiling. The check is kept as a hard invariant: a
  // decoder that ever buffers more than one maximum frame is a defect.
  if (buffer_.size() - offset_ > *ceiling) {
    return Status::fail(ErrorCode::OversizePayload,
                        "decoder buffered more than one maximum frame",
                        std::to_string(buffer_.size() - offset_));
  }
  return Status::ok();
}

Status FrameDecoder::finish(std::string_view what) const {
  if (buffered() != 0) {
    return Status::fail(ErrorCode::TruncatedFrame,
                        "stream ended with a partially received frame",
                        std::string(what) + ": " + std::to_string(buffered()) + " byte(s)");
  }
  return Status::ok();
}

}  // namespace cf
