// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Real socket transport.
//
// The runtime's distributed behaviour is proven over loopback TCP sockets across
// independent OS processes. There is no in-memory shortcut: the same
// FramedConnection type is used by the controller, the target agent and the
// inspection CLI.
//
// Deadlines are absolute monotonic millisecond values. A zero deadline means
// "do not wait"; a negative deadline means "wait forever". Every wait is
// interruptible: Socket::interrupt() performs a socket shutdown, which is the
// one operation that is safe to call concurrently with a blocked recv()/send()
// on the same handle. Listener::interrupt() is a flag plus a bounded poll
// interval, because cancelling accept() by closing the handle is not portable.

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "cf/frame.hpp"
#include "cf/result.hpp"

namespace cf {

/// Process-wide socket subsystem. Initializes Winsock on Windows exactly once.
[[nodiscard]] Status ensureSocketRuntime();

struct Endpoint {
  std::string host;
  std::uint16_t port{0};

  [[nodiscard]] std::string str() const;
  [[nodiscard]] bool isSet() const noexcept { return !host.empty() && port != 0; }
};

/// Strict "host:port" parsing for deployment instructions and CLI arguments.
/// Rejects empty hosts, non-numeric or out-of-range ports and trailing garbage.
[[nodiscard]] Result<Endpoint> parseEndpoint(std::string_view text);

class Socket final {
 public:
  Socket() noexcept = default;
  ~Socket();

  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;

  [[nodiscard]] bool valid() const noexcept;
  void close() noexcept;
  /// Unblocks a concurrent read/write without closing the handle.
  void interrupt() noexcept;
  [[nodiscard]] Status setNoDelay(bool enabled);
  [[nodiscard]] Status setReuseAddress(bool enabled);
  /// Largest single read the transport will issue, so a caller cannot request an
  /// unreasonable buffer.
  [[nodiscard]] static constexpr std::size_t maxReadBytes() noexcept { return 1u << 20; }

  [[nodiscard]] Result<std::size_t> readSome(std::span<std::uint8_t> out,
                                             std::int64_t deadlineMillis);
  [[nodiscard]] Status writeAll(std::span<const std::uint8_t> data,
                                std::int64_t deadlineMillis);
  [[nodiscard]] Endpoint peer() const;

  [[nodiscard]] std::uintptr_t handle() const noexcept { return handle_; }
  /// True once interrupt() has been called.
  [[nodiscard]] bool interrupted() const noexcept {
    return interrupted_.load(std::memory_order_relaxed);
  }

 private:
  friend class Listener;
  friend Result<Socket> connectTcp(const std::string& host, std::uint16_t port,
                                   std::int64_t timeoutMillis);
  explicit Socket(std::uintptr_t handle) noexcept : handle_(handle) {}

  std::uintptr_t handle_{0};
  /// Set by interrupt(). A blocked read or write observes it within one poll
  /// slice, which is what makes cancellation prompt on platforms where a
  /// shutdown() does not wake a select() that is already blocked in the kernel.
  std::atomic<bool> interrupted_{false};
};

class Listener final {
 public:
  Listener() noexcept = default;
  ~Listener();

  Listener(const Listener&) = delete;
  Listener& operator=(const Listener&) = delete;

  [[nodiscard]] static Result<std::unique_ptr<Listener>> bindTcp(const std::string& host,
                                                                 std::uint16_t port,
                                                                 int backlog);
  /// Waits for a connection until the deadline. A deadline that elapses yields
  /// ErrorCode::PeerIdleTimeout so the caller can loop without treating it as a
  /// failure. After interrupt() the call returns ErrorCode::ShuttingDown.
  [[nodiscard]] Result<Socket> accept(std::int64_t deadlineMillis);
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] std::string host() const { return host_; }
  void close() noexcept;
  void interrupt() noexcept { interrupted_.store(true, std::memory_order_relaxed); }
  [[nodiscard]] bool interrupted() const noexcept {
    return interrupted_.load(std::memory_order_relaxed);
  }
  [[nodiscard]] bool valid() const noexcept { return handle_ != 0; }

 private:
  std::uintptr_t handle_{0};
  std::uint16_t port_{0};
  std::string host_;
  std::atomic<bool> interrupted_{false};
};

[[nodiscard]] Result<Socket> connectTcp(const std::string& host, std::uint16_t port,
                                        std::int64_t timeoutMillis);

/// Frame-oriented connection over a Socket. Owns its socket and never shares it:
/// exactly one thread may be inside receive() at a time, and any thread may call
/// interrupt().
class FramedConnection final {
 public:
  FramedConnection(Socket socket, std::uint32_t maxPayloadBytes) noexcept;

  [[nodiscard]] Status send(FrameType type, std::uint16_t flags,
                            std::span<const std::uint8_t> payload, std::int64_t deadlineMillis);
  /// Returns the next frame, or ErrorCode::PeerIdleTimeout when the deadline
  /// elapsed with nothing received, or ConnectionClosed when the peer closed
  /// cleanly. A truncated frame at end-of-stream is reported as TruncatedFrame,
  /// never silently dropped.
  [[nodiscard]] Result<Frame> receive(std::int64_t deadlineMillis);

  void interrupt() noexcept { socket_.interrupt(); }
  void close() noexcept { socket_.close(); }
  [[nodiscard]] bool valid() const noexcept { return socket_.valid(); }
  [[nodiscard]] std::uint32_t maxPayloadBytes() const noexcept { return maxPayloadBytes_; }
  [[nodiscard]] Endpoint peer() const { return socket_.peer(); }
  /// Bytes handed to send plus bytes received, for accounting and for reports.
  [[nodiscard]] std::uint64_t bytesSent() const noexcept { return bytesSent_; }
  [[nodiscard]] std::uint64_t bytesReceived() const noexcept { return bytesReceived_; }

 private:
  Socket socket_;
  std::uint32_t maxPayloadBytes_;
  FrameDecoder decoder_;
  std::vector<Frame> ready_;
  std::size_t readyOffset_{0};
  std::vector<std::uint8_t> readBuffer_;
  std::uint64_t bytesSent_{0};
  std::uint64_t bytesReceived_{0};
};

}  // namespace cf
