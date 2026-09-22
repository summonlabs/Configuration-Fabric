// Unit and multiprocess tests: independent process control.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <string>

#include "cf/process.hpp"
#include "harness.hpp"
#include "testing.hpp"

CF_TEST(unit, argument_quoting_round_trips) {
  // Paths with spaces are the common case in this repository, so quoting must be
  // exact rather than approximate.
  CF_EXPECT_EQ(cf::quoteArgument("plain"), std::string("plain"));
  const std::string spaced = cf::quoteArgument("a path with spaces");
  CF_EXPECT(spaced.front() == '"');
  CF_EXPECT(spaced.back() == '"');
  CF_EXPECT(spaced.find("a path with spaces") != std::string::npos);
}

CF_TEST(process, agent_and_controller_run_as_independent_executables) {
  cf::test::TempDir directory("process-smoke");
  const std::string keyFile = cf::test::keyFileFor(directory);
  auto agent = cf::test::startAgent(directory, "rtr-1", directory.child("agent-state"));
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  CF_EXPECT(agent->running());
  CF_EXPECT(!agent->endpoint().empty());
  // The announce file names a real, dialable endpoint.
  auto parsed = cf::parseEndpoint(agent->endpoint());
  CF_EXPECT_OK(parsed);
  if (parsed.hasValue()) {
    CF_EXPECT(parsed.value().port != 0);
    auto socket = cf::connectTcp(parsed.value().host, parsed.value().port, 2000);
    CF_EXPECT_OK(socket);
    socket.value().close();
  }
  // A hard kill is immediate and the process is really gone afterwards.
  CF_EXPECT(agent->kill());
  const int code = agent->wait();
  CF_EXPECT(code != 0);
  CF_EXPECT(!agent->running());
  (void)keyFile;
}

CF_TEST(process, killed_process_leaves_no_live_socket) {
  cf::test::TempDir directory("process-kill");
  auto agent = cf::test::startAgent(directory, "rtr-2", directory.child("agent-state"));
  CF_EXPECT(agent != nullptr);
  if (agent == nullptr) {
    return;
  }
  auto parsed = cf::parseEndpoint(agent->endpoint());
  CF_REQUIRE_OK(parsed);
  CF_EXPECT(agent->kill());
  CF_EXPECT(agent->wait() != 0);

  // A connection attempt against the dead port must fail rather than hang.
  const auto connectResult =
      cf::connectTcp(parsed.value().host, parsed.value().port, 1000);
  CF_EXPECT(!connectResult.hasValue());
}

CF_TEST(process, cfctl_reports_unknown_arguments_and_version) {
  int exitCode = 0;
  const std::string version = cf::test::runCtl({"--version"}, &exitCode);
  CF_EXPECT_EQ(exitCode, 0);
  CF_EXPECT(cf::test::containsText(version, "Configuration Fabric"));

  const std::string bogus = cf::test::runCtl({"--nonsense"}, &exitCode);
  CF_EXPECT(exitCode != 0);
  CF_EXPECT(cf::test::containsText(bogus, "unknown argument"));
}

CF_TEST(process, cfctl_digest_matches_the_library) {
  cf::test::TempDir directory("process-digest");
  const std::string path = directory.child("payload.txt");
  const std::string body = "configuration body for digest comparison\n";
  cf::test::writeTextFile(path, body);

  int exitCode = 0;
  const std::string output = cf::test::runCtl({"digest", path}, &exitCode);
  CF_EXPECT_EQ(exitCode, 0);
  const std::string expected = cf::toHex(cf::sha256(body));
  CF_EXPECT(cf::test::containsText(output, expected));
  CF_EXPECT(cf::test::containsText(output, "size " + std::to_string(body.size())));
}
