// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Inspection and operations control channel.
//
// cfctl talks to a running distributor over a real loopback socket using the
// same framing as the agent protocol, on its own message types. The channel is
// authenticated with the same shared secret; an unauthenticated control client
// is rejected before it can read a single byte of state.
//
// Every command is a read or an explicitly-named operation. Command output is
// deterministic: identical durable state produces byte-identical text.

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "cf/distributor.hpp"
#include "cf/result.hpp"
#include "cf/transport.hpp"

namespace cf {

/// One parsed control request.
struct ControlRequest {
  std::string command;
  std::vector<std::string> arguments;
};

/// Splits one command line into a request. Quoting with double quotes is
/// supported so paths with spaces can be passed.
[[nodiscard]] Result<ControlRequest> parseControlLine(std::string_view line);

/// Executes one request against a live distributor. Returns the rendered body.
[[nodiscard]] Result<std::string> executeControlCommand(Distributor& distributor,
                                                        const ControlRequest& request);

/// Serves one control connection to completion. key is the shared secret used by
/// the agent protocol; an unauthenticated client is rejected before any state is
/// rendered.
[[nodiscard]] Status serveControlConnection(Distributor& distributor, Socket socket,
                                            const HmacKey& key);

/// Client side: connects, authenticates and runs one command.
[[nodiscard]] Result<std::string> runControlCommand(const Endpoint& endpoint, const HmacKey& key,
                                                    bool authenticate,
                                                    const ControlRequest& request);

/// The command catalogue, used by --help and by the README generator.
[[nodiscard]] std::string renderControlCommands();

}  // namespace cf
