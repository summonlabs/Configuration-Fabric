// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/transport.hpp"

#include <algorithm>
#include <array>
#include <string>

#include "cf/checked.hpp"
#include "cf/contract.hpp"
#include "cf/log.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace cf {
namespace {

constexpr std::string_view kComponent = "transport";
/// Cancellation poll interval for accept(). Bounds how long a shutdown can take
/// without closing a listening handle from another thread.
constexpr std::int64_t kAcceptPollMillis = 50;

#if defined(_WIN32)
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidNative = INVALID_SOCKET;
constexpr int kShutdownBoth = SD_BOTH;

[[nodiscard]] int lastSocketErrorCode() noexcept { return WSAGetLastError(); }
[[nodiscard]] bool isInterruptedError(int code) noexcept { return code == WSAEINTR; }
[[nodiscard]] bool wouldBlock(int code) noexcept { return code == WSAEWOULDBLOCK; }

[[nodiscard]] Status mapSocketError(int code, ErrorCode fallback, std::string_view what) {
  const std::string detail = std::string(what) + " (wsa=" + std::to_string(code) + ")";
  switch (code) {
    case WSAECONNREFUSED:
      return Status::fail(ErrorCode::ConnectionRefused, "connection refused", detail);
    case WSAECONNRESET:
    case WSAECONNABORTED:
      return Status::fail(ErrorCode::ConnectionReset, "connection reset by peer", detail);
    case WSAETIMEDOUT:
      return Status::fail(ErrorCode::PeerIdleTimeout, "socket operation timed out", detail);
    case WSAENOTSOCK:
    case WSAEBADF:
      return Status::fail(ErrorCode::ConnectionClosed, "socket is no longer usable", detail);
    default:
      return Status::fail(fallback, std::string(what), detail);
  }
}

[[nodiscard]] Status setNonBlocking(NativeSocket handle, bool enabled) {
  u_long mode = enabled ? 1u : 0u;
  if (::ioctlsocket(handle, FIONBIO, &mode) != 0) {
    return mapSocketError(lastSocketErrorCode(), ErrorCode::IoFailure,
                          "cannot change socket blocking mode");
  }
  return Status::ok();
}

[[nodiscard]] Status closeNative(NativeSocket handle) noexcept {
  ::closesocket(handle);
  return Status::ok();
}

#else
using NativeSocket = int;
constexpr NativeSocket kInvalidNative = -1;
constexpr int kShutdownBoth = SHUT_RDWR;

[[nodiscard]] int lastSocketErrorCode() noexcept { return errno; }
[[nodiscard]] bool isInterruptedError(int code) noexcept { return code == EINTR; }
[[nodiscard]] bool wouldBlock(int code) noexcept { return code == EWOULDBLOCK || code == EAGAIN; }

[[nodiscard]] Status mapSocketError(int code, ErrorCode fallback, std::string_view what) {
  const std::string detail = std::string(what) + " (errno=" + std::to_string(code) + ")";
  switch (code) {
    case ECONNREFUSED:
      return Status::fail(ErrorCode::ConnectionRefused, "connection refused", detail);
    case ECONNRESET:
    case ECONNABORTED:
    case EPIPE:
      return Status::fail(ErrorCode::ConnectionReset, "connection reset by peer", detail);
    case ETIMEDOUT:
      return Status::fail(ErrorCode::PeerIdleTimeout, "socket operation timed out", detail);
    case EBADF:
      return Status::fail(ErrorCode::ConnectionClosed, "socket is no longer usable", detail);
    default:
      return Status::fail(fallback, std::string(what), detail);
  }
}

[[nodiscard]] Status setNonBlocking(NativeSocket handle, bool enabled) {
  const int flags = ::fcntl(handle, F_GETFL, 0);
  if (flags < 0) {
    return mapSocketError(lastSocketErrorCode(), ErrorCode::IoFailure,
                          "cannot read socket flags");
  }
  const int updated = enabled ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
  if (::fcntl(handle, F_SETFL, updated) < 0) {
    return mapSocketError(lastSocketErrorCode(), ErrorCode::IoFailure,
                          "cannot change socket blocking mode");
  }
  return Status::ok();
}

[[nodiscard]] Status closeNative(NativeSocket handle) noexcept {
  ::close(handle);
  return Status::ok();
}

#endif

[[nodiscard]] std::int64_t remainingMillis(std::int64_t deadlineMillis) noexcept {
  if (deadlineMillis == 0) {
    return 0;
  }
  if (deadlineMillis < 0) {
    return -1;
  }
  const std::int64_t now = monotonicMillis();
  return deadlineMillis > now ? (deadlineMillis - now) : 0;
}

/// Waits for readability or writability. Ok when ready, PeerIdleTimeout when the
/// deadline elapsed first. A negative deadline blocks indefinitely.
[[nodiscard]] Status waitFor(NativeSocket handle, bool forRead, std::int64_t deadlineMillis) {
  for (;;) {
    const std::int64_t remaining = remainingMillis(deadlineMillis);
    if (deadlineMillis >= 0 && remaining == 0) {
      return Status::fail(ErrorCode::PeerIdleTimeout, "socket deadline elapsed before readiness");
    }
    fd_set readSet;
    fd_set writeSet;
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    if (forRead) {
      FD_SET(handle, &readSet);
    } else {
      FD_SET(handle, &writeSet);
    }
    timeval timeout{};
    timeval* timeoutPtr = nullptr;
    if (deadlineMillis >= 0) {
      const std::int64_t slice = (remaining < 0) ? 0 : remaining;
      timeout.tv_sec = static_cast<long>(slice / 1000);
      timeout.tv_usec = static_cast<long>((slice % 1000) * 1000);
      timeoutPtr = &timeout;
    }
#if defined(_WIN32)
    const int ready = ::select(0, forRead ? &readSet : nullptr, forRead ? nullptr : &writeSet,
                               nullptr, timeoutPtr);
#else
    const int ready = ::select(static_cast<int>(handle) + 1, forRead ? &readSet : nullptr,
                               forRead ? nullptr : &writeSet, nullptr, timeoutPtr);
#endif
    if (ready > 0) {
      return Status::ok();
    }
    if (ready == 0) {
      return Status::fail(ErrorCode::PeerIdleTimeout, "socket deadline elapsed before readiness");
    }
    const int error = lastSocketErrorCode();
    if (isInterruptedError(error)) {
      continue;
    }
    return mapSocketError(error, ErrorCode::IoFailure, "socket readiness wait failed");
  }
}

[[nodiscard]] Endpoint endpointOf(const sockaddr_storage& storage) {
  Endpoint endpoint;
  std::array<char, INET6_ADDRSTRLEN> buffer{};
  if (storage.ss_family == AF_INET) {
    const auto* address = reinterpret_cast<const sockaddr_in*>(&storage);
    if (::inet_ntop(AF_INET, &address->sin_addr, buffer.data(),
                    static_cast<socklen_t>(buffer.size())) != nullptr) {
      endpoint.host.assign(buffer.data());
    }
    endpoint.port = ntohs(address->sin_port);
  } else if (storage.ss_family == AF_INET6) {
    const auto* address = reinterpret_cast<const sockaddr_in6*>(&storage);
    if (::inet_ntop(AF_INET6, &address->sin6_addr, buffer.data(),
                    static_cast<socklen_t>(buffer.size())) != nullptr) {
      endpoint.host.assign(buffer.data());
    }
    endpoint.port = ntohs(address->sin6_port);
  }
  return endpoint;
}

}  // namespace

std::string Endpoint::str() const { return host + ":" + std::to_string(port); }

Result<Endpoint> parseEndpoint(std::string_view text) {
  if (text.empty() || text.size() > 128) {
    return Result<Endpoint>::fail(ErrorCode::InvalidArgument, "endpoint text is empty or too long");
  }
  const std::size_t colon = text.rfind(':');
  if (colon == std::string_view::npos || colon == 0 || colon + 1 >= text.size()) {
    return Result<Endpoint>::fail(ErrorCode::InvalidArgument,
                                  "endpoint must be written as host:port", std::string(text));
  }
  const std::string_view host = text.substr(0, colon);
  const std::string_view portText = text.substr(colon + 1);
  for (const char c : host) {
    const unsigned char raw = static_cast<unsigned char>(c);
    const bool digit = raw >= '0' && raw <= '9';
    const bool upper = raw >= 'A' && raw <= 'Z';
    const bool lower = raw >= 'a' && raw <= 'z';
    const bool punctuation = c == '.' || c == '-' || c == '_' || c == ':';
    if (!digit && !upper && !lower && !punctuation) {
      return Result<Endpoint>::fail(ErrorCode::InvalidArgument,
                                    "endpoint host contains an unsupported character",
                                    std::string(text));
    }
  }
  std::uint32_t port = 0;
  for (const char c : portText) {
    if (c < '0' || c > '9') {
      return Result<Endpoint>::fail(ErrorCode::InvalidArgument,
                                    "endpoint port is not a decimal integer", std::string(text));
    }
    port = (port * 10u) + static_cast<std::uint32_t>(c - '0');
    if (port > 65535u) {
      return Result<Endpoint>::fail(ErrorCode::OutOfRange, "endpoint port is out of range",
                                    std::string(text));
    }
  }
  Endpoint endpoint;
  endpoint.host.assign(host);
  endpoint.port = static_cast<std::uint16_t>(port);
  return Result<Endpoint>::ok(std::move(endpoint));
}

Status ensureSocketRuntime() {
#if defined(_WIN32)
  static const Status initialized = [] {
    WSADATA data{};
    const int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
      return Status::fail(ErrorCode::Internal, "WSAStartup failed", std::to_string(result));
    }
    return Status::ok();
  }();
  return initialized;
#else
  return Status::ok();
#endif
}

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) { other.handle_ = 0; }

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = 0;
  }
  return *this;
}

Socket::~Socket() { close(); }

bool Socket::valid() const noexcept { return handle_ != 0; }

void Socket::close() noexcept {
  if (handle_ == 0) {
    return;
  }
  const NativeSocket native = static_cast<NativeSocket>(handle_);
  handle_ = 0;
  (void)closeNative(native);
}

void Socket::interrupt() noexcept {
  if (handle_ == 0) {
    return;
  }
  // shutdown() is the only socket call that may run concurrently with a blocked
  // recv()/send() on the same handle. It makes those calls return promptly
  // without invalidating the handle.
  ::shutdown(static_cast<NativeSocket>(handle_), kShutdownBoth);
}

Status Socket::setNoDelay(bool enabled) {
  if (handle_ == 0) {
    return Status::fail(ErrorCode::ConnectionClosed, "socket is not open");
  }
  const int value = enabled ? 1 : 0;
  if (::setsockopt(static_cast<NativeSocket>(handle_), IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
    return mapSocketError(lastSocketErrorCode(), ErrorCode::IoFailure,
                          "cannot configure TCP_NODELAY");
  }
  return Status::ok();
}

Status Socket::setReuseAddress(bool enabled) {
  if (handle_ == 0) {
    return Status::fail(ErrorCode::ConnectionClosed, "socket is not open");
  }
  const int value = enabled ? 1 : 0;
  if (::setsockopt(static_cast<NativeSocket>(handle_), SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
    return mapSocketError(lastSocketErrorCode(), ErrorCode::IoFailure,
                          "cannot configure SO_REUSEADDR");
  }
  return Status::ok();
}

Result<std::size_t> Socket::readSome(std::span<std::uint8_t> out, std::int64_t deadlineMillis) {
  if (handle_ == 0) {
    return Result<std::size_t>::fail(ErrorCode::ConnectionClosed, "socket is not open");
  }
  if (out.empty()) {
    return Result<std::size_t>::fail(ErrorCode::InvalidArgument, "read buffer must not be empty");
  }
  if (out.size() > maxReadBytes()) {
    return Result<std::size_t>::fail(ErrorCode::CapacityExceeded,
                                     "read request exceeds the transport maximum",
                                     std::to_string(out.size()));
  }
  const NativeSocket handle = static_cast<NativeSocket>(handle_);
  for (;;) {
    CF_TRY(waitFor(handle, true, deadlineMillis));
#if defined(_WIN32)
    const int received =
        ::recv(handle, reinterpret_cast<char*>(out.data()), static_cast<int>(out.size()), 0);
#else
    const ssize_t received = ::recv(handle, out.data(), out.size(), 0);
#endif
    if (received > 0) {
      return Result<std::size_t>::ok(static_cast<std::size_t>(received));
    }
    if (received == 0) {
      return Result<std::size_t>::fail(ErrorCode::ConnectionClosed, "peer closed the connection");
    }
    const int error = lastSocketErrorCode();
    if (wouldBlock(error)) {
      continue;
    }
    return Result<std::size_t>::fail(
        mapSocketError(error, ErrorCode::IoFailure, "socket read failed"));
  }
}

Status Socket::writeAll(std::span<const std::uint8_t> data, std::int64_t deadlineMillis) {
  if (handle_ == 0) {
    return Status::fail(ErrorCode::ConnectionClosed, "socket is not open");
  }
  const NativeSocket handle = static_cast<NativeSocket>(handle_);
  std::size_t offset = 0;
  while (offset < data.size()) {
    CF_TRY(waitFor(handle, false, deadlineMillis));
    const std::size_t remaining = data.size() - offset;
    const std::size_t chunk = std::min<std::size_t>(remaining, 1u << 20);
#if defined(_WIN32)
    const int sent = ::send(handle, reinterpret_cast<const char*>(data.data() + offset),
                            static_cast<int>(chunk), 0);
#else
    const ssize_t sent = ::send(handle, data.data() + offset, chunk, MSG_NOSIGNAL);
#endif
    if (sent > 0) {
      offset += static_cast<std::size_t>(sent);
      continue;
    }
    const int error = lastSocketErrorCode();
    if (wouldBlock(error)) {
      continue;
    }
    return mapSocketError(error, ErrorCode::IoFailure, "socket write failed");
  }
  return Status::ok();
}

Endpoint Socket::peer() const {
  Endpoint endpoint;
  if (handle_ == 0) {
    return endpoint;
  }
  sockaddr_storage storage{};
  socklen_t length = static_cast<socklen_t>(sizeof(storage));
  if (::getpeername(static_cast<NativeSocket>(handle_), reinterpret_cast<sockaddr*>(&storage),
                    &length) != 0) {
    return endpoint;
  }
  return endpointOf(storage);
}

Listener::~Listener() { close(); }

void Listener::close() noexcept {
  if (handle_ == 0) {
    return;
  }
  const NativeSocket native = static_cast<NativeSocket>(handle_);
  handle_ = 0;
  (void)closeNative(native);
}

Result<std::unique_ptr<Listener>> Listener::bindTcp(const std::string& host, std::uint16_t port,
                                                    int backlog) {
  CF_TRY(ensureSocketRuntime());
  if (backlog <= 0) {
    return Result<std::unique_ptr<Listener>>::fail(ErrorCode::InvalidArgument,
                                                   "listen backlog must be positive");
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  const std::string service = std::to_string(port);
  addrinfo* results = nullptr;
  const int resolved =
      ::getaddrinfo(host.empty() ? nullptr : host.c_str(), service.c_str(), &hints, &results);
  if (resolved != 0 || results == nullptr) {
    return Result<std::unique_ptr<Listener>>::fail(ErrorCode::OpenFailed,
                                                   "cannot resolve listen address",
                                                   host + ":" + service);
  }

  std::unique_ptr<Listener> listener;
  Status failure = Status::fail(ErrorCode::OpenFailed, "no usable listen address");
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    const NativeSocket handle =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == kInvalidNative) {
      continue;
    }
    const int enable = 1;
    ::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&enable),
                 sizeof(enable));
    if (::bind(handle, candidate->ai_addr, static_cast<socklen_t>(candidate->ai_addrlen)) != 0) {
      failure = mapSocketError(lastSocketErrorCode(), ErrorCode::OpenFailed,
                               "cannot bind listen socket");
      (void)closeNative(handle);
      continue;
    }
    if (::listen(handle, backlog) != 0) {
      failure = mapSocketError(lastSocketErrorCode(), ErrorCode::OpenFailed,
                               "cannot listen on socket");
      (void)closeNative(handle);
      continue;
    }
    sockaddr_storage bound{};
    socklen_t boundLength = static_cast<socklen_t>(sizeof(bound));
    if (::getsockname(handle, reinterpret_cast<sockaddr*>(&bound), &boundLength) != 0) {
      failure = mapSocketError(lastSocketErrorCode(), ErrorCode::OpenFailed,
                               "cannot read bound socket address");
      (void)closeNative(handle);
      continue;
    }
    const Endpoint endpoint = endpointOf(bound);
    listener.reset(new Listener());
    listener->handle_ = static_cast<std::uintptr_t>(handle);
    listener->port_ = endpoint.port;
    listener->host_ = endpoint.host;
    failure = Status::ok();
    break;
  }
  ::freeaddrinfo(results);
  if (!failure) {
    return Result<std::unique_ptr<Listener>>::fail(failure);
  }
  return Result<std::unique_ptr<Listener>>::ok(std::move(listener));
}

Result<Socket> Listener::accept(std::int64_t deadlineMillis) {
  if (handle_ == 0) {
    return Result<Socket>::fail(ErrorCode::ConnectionClosed, "listener is closed");
  }
  const NativeSocket handle = static_cast<NativeSocket>(handle_);
  for (;;) {
    if (interrupted()) {
      return Result<Socket>::fail(ErrorCode::ShuttingDown, "listener was interrupted");
    }
    const std::int64_t now = monotonicMillis();
    std::int64_t slice = now + kAcceptPollMillis;
    if (deadlineMillis >= 0 && deadlineMillis < slice) {
      slice = deadlineMillis;
    }
    const Status ready = waitFor(handle, true, slice);
    if (!ready) {
      if (ready.code() == ErrorCode::PeerIdleTimeout) {
        if (deadlineMillis >= 0 && monotonicMillis() >= deadlineMillis) {
          return Result<Socket>::fail(ErrorCode::PeerIdleTimeout,
                                      "no connection arrived before the deadline");
        }
        continue;
      }
      return Result<Socket>::fail(ready.error());
    }
    sockaddr_storage storage{};
    socklen_t length = static_cast<socklen_t>(sizeof(storage));
    const NativeSocket accepted = ::accept(handle, reinterpret_cast<sockaddr*>(&storage), &length);
    if (accepted == kInvalidNative) {
      const int error = lastSocketErrorCode();
      if (wouldBlock(error)) {
        continue;
      }
      return Result<Socket>::fail(
          mapSocketError(error, ErrorCode::IoFailure, "accept failed"));
    }
    Socket socket(static_cast<std::uintptr_t>(accepted));
    const Status configured = socket.setNoDelay(true);
    if (!configured) {
      Logger::global().warn(kComponent, "accepted socket without TCP_NODELAY: " + configured.str());
    }
    return Result<Socket>::ok(std::move(socket));
  }
}

Result<Socket> connectTcp(const std::string& host, std::uint16_t port,
                          std::int64_t timeoutMillis) {
  CF_TRY(ensureSocketRuntime());
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  const std::string service = std::to_string(port);
  addrinfo* results = nullptr;
  const int resolved = ::getaddrinfo(host.c_str(), service.c_str(), &hints, &results);
  if (resolved != 0 || results == nullptr) {
    return Result<Socket>::fail(ErrorCode::OpenFailed, "cannot resolve peer address",
                                host + ":" + service);
  }

  Status failure = Status::fail(ErrorCode::ConnectionRefused, "no usable peer address");
  Socket connected;
  const std::int64_t deadline = monotonicMillis() + std::max<std::int64_t>(timeoutMillis, 1);
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    const NativeSocket handle =
        ::socket(candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol);
    if (handle == kInvalidNative) {
      continue;
    }
    // Non-blocking connect with a bounded wait keeps the connect budget honest on
    // a host where the SYN may be silently dropped.
    Status mode = setNonBlocking(handle, true);
    if (!mode) {
      (void)closeNative(handle);
      failure = mode;
      continue;
    }
    const int rc =
        ::connect(handle, candidate->ai_addr, static_cast<socklen_t>(candidate->ai_addrlen));
    bool connectedNow = (rc == 0);
    if (!connectedNow) {
      const int error = lastSocketErrorCode();
#if defined(_WIN32)
      const bool inProgress = (error == WSAEWOULDBLOCK) || (error == WSAEINPROGRESS) ||
                              (error == WSAEALREADY);
#else
      const bool inProgress = (error == EINPROGRESS) || (error == EALREADY);
#endif
      if (!inProgress && !wouldBlock(error)) {
        failure = mapSocketError(error, ErrorCode::ConnectionRefused, "connect failed");
        (void)closeNative(handle);
        continue;
      }
      const Status wait = waitFor(handle, false, deadline);
      if (!wait) {
        failure = wait;
        (void)closeNative(handle);
        continue;
      }
      int socketError = 0;
      socklen_t errorLength = static_cast<socklen_t>(sizeof(socketError));
      if (::getsockopt(handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socketError),
                       &errorLength) != 0 ||
          socketError != 0) {
        failure = mapSocketError(socketError, ErrorCode::ConnectionRefused, "connect failed");
        (void)closeNative(handle);
        continue;
      }
      connectedNow = true;
    }
    if (!connectedNow) {
      continue;
    }
    mode = setNonBlocking(handle, false);
    if (!mode) {
      (void)closeNative(handle);
      failure = mode;
      continue;
    }
    connected = Socket(static_cast<std::uintptr_t>(handle));
    failure = Status::ok();
    break;
  }
  ::freeaddrinfo(results);
  if (!failure) {
    return Result<Socket>::fail(failure);
  }
  const Status configured = connected.setNoDelay(true);
  if (!configured) {
    Logger::global().warn(kComponent, "connected socket without TCP_NODELAY: " + configured.str());
  }
  return Result<Socket>::ok(std::move(connected));
}

FramedConnection::FramedConnection(Socket socket, std::uint32_t maxPayloadBytes) noexcept
    : socket_(std::move(socket)),
      maxPayloadBytes_(maxPayloadBytes),
      decoder_(maxPayloadBytes),
      readBuffer_(64u * 1024u) {}

Status FramedConnection::send(FrameType type, std::uint16_t flags,
                              std::span<const std::uint8_t> payload,
                              std::int64_t deadlineMillis) {
  auto encoded = encodeFrame(type, flags, payload, maxPayloadBytes_);
  if (!encoded) {
    return Status::fail(encoded.error());
  }
  CF_TRY(socket_.writeAll(encoded.value(), deadlineMillis));
  const auto next = checkedAdd<std::uint64_t>(bytesSent_, encoded.value().size());
  bytesSent_ = next ? *next : bytesSent_;
  return Status::ok();
}

Result<Frame> FramedConnection::receive(std::int64_t deadlineMillis) {
  for (;;) {
    if (readyOffset_ < ready_.size()) {
      Frame frame = std::move(ready_[readyOffset_]);
      readyOffset_ += 1;
      if (readyOffset_ == ready_.size()) {
        ready_.clear();
        readyOffset_ = 0;
      }
      return Result<Frame>::ok(std::move(frame));
    }
    auto read = socket_.readSome(readBuffer_, deadlineMillis);
    if (!read) {
      if (read.error().code() == ErrorCode::ConnectionClosed) {
        // A clean close with a half-received frame is a truncated stream, not a
        // normal close. Report it precisely.
        CF_TRY(decoder_.finish("connection closed"));
      }
      return Result<Frame>::fail(read.error());
    }
    const std::span<const std::uint8_t> received(readBuffer_.data(), read.value());
    const auto next = checkedAdd<std::uint64_t>(bytesReceived_, read.value());
    bytesReceived_ = next ? *next : bytesReceived_;
    CF_TRY(decoder_.feed(received, ready_));
    if (ready_.empty()) {
      continue;
    }
  }
}

}  // namespace cf
