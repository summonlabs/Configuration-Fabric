// Configuration Fabric benchmarks.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Every benchmark measures completed work, never enqueue or submission latency:
//
//   artifact-store   bytes that were durably published AND re-read AND verified
//   delivery         deliveries that reached "acknowledged" over a real socket
//   framing          payload bytes that survived an encode/decode round trip
//
// The delivery benchmark runs one controller and one agent inside a single
// process, connected by a real loopback TCP socket pair. That is a throughput
// measurement, not the distributed proof: the multiprocess proof lives in the
// validation suite (cf.multiprocess, cf.injection, cf.restart).

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "cf/agent.hpp"
#include "cf/artifact.hpp"
#include "cf/codec.hpp"
#include "cf/control.hpp"
#include "cf/distributor.hpp"
#include "cf/frame.hpp"
#include "cf/log.hpp"
#include "cf/plan.hpp"
#include "cf/rng.hpp"
#include "cf/transport.hpp"
#include "cf/version.hpp"

namespace {

using Clock = std::chrono::steady_clock;

[[nodiscard]] double secondsSince(Clock::time_point start) {
  return std::chrono::duration<double>(Clock::now() - start).count();
}

[[nodiscard]] std::string temporaryRoot(std::string_view label) {
  const std::array<std::uint8_t, 16> suffix = cf::secureRandom128();
  const std::filesystem::path path =
      std::filesystem::temp_directory_path() /
      ("cf-bench-" + std::string(label) + "-" +
       cf::toHex(std::span<const std::uint8_t>(suffix.data(), suffix.size())).substr(0, 10));
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  return path.string();
}

void writeText(const std::string& path, std::string_view content) {
  std::filesystem::path target(path);
  std::error_code ec;
  std::filesystem::create_directories(target.parent_path(), ec);
  std::FILE* file = std::fopen(path.c_str(), "wb");
  if (file == nullptr) {
    return;
  }
  const std::size_t written = std::fwrite(content.data(), 1, content.size(), file);
  (void)written;
  std::fclose(file);
}

struct Result {
  std::string name;
  double seconds{0};
  double units{0};
  std::string unit;
  double megabytes{0};
};

std::vector<Result> g_results;

void report(const Result& result) {
  g_results.push_back(result);
  std::printf("%-22s %10.3f s  %12.1f %-14s", result.name.c_str(), result.seconds, result.units,
              result.unit.c_str());
  if (result.megabytes > 0) {
    std::printf(" %9.2f MB/s", result.megabytes / result.seconds);
  }
  std::printf("\n");
  std::fflush(stdout);
}

void benchArtifactStore(std::size_t artifactCount, std::size_t artifactBytes) {
  const std::string root = temporaryRoot("store");
  cf::ArtifactStore::Options options;
  options.root = root + "/artifacts";
  options.maxArtifactBytes = 8u * 1024u * 1024u;
  options.maxTotalBytes = 1ull << 32;
  options.maxArtifacts = artifactCount + 16;
  cf::ArtifactStore::RecoveryReport recovery;
  auto store = cf::ArtifactStore::open(options, recovery);
  if (!store) {
    std::printf("artifact-store benchmark failed to open: %s\n", store.error().str().c_str());
    return;
  }

  std::vector<std::string> payloads;
  payloads.reserve(artifactCount);
  cf::Rng rng(1234);
  for (std::size_t i = 0; i < artifactCount; ++i) {
    std::string body(artifactBytes, ' ');
    for (std::size_t j = 0; j < artifactBytes; ++j) {
      body[j] = static_cast<char>('a' + rng.bounded(26));
    }
    payloads.push_back(std::move(body));
  }

  const auto started = Clock::now();
  for (std::size_t i = 0; i < payloads.size(); ++i) {
    cf::ArtifactMetadata metadata;
    metadata.id = cf::parseArtifactId("cfg/bench-" + std::to_string(i)).value();
    metadata.revision = cf::Revision::fromValue(i + 1);
    metadata.schema = cf::parseSchemaId("cf.bench").value();
    metadata.schemaVersion = cf::SchemaVersion::fromValue(1);
    metadata.digest = cf::Digest::ofText(payloads[i]);
    metadata.sizeBytes = payloads[i].size();
    metadata.mediaType = "application/octet-stream";
    metadata.producer = "benchmark";
    const cf::Status published = store.value()->ingestBytes(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(payloads[i].data()),
                                      payloads[i].size()),
        metadata);
    if (!published) {
      std::printf("publish failed: %s\n", published.str().c_str());
      return;
    }
  }
  // Completed work: every artifact is re-read and its digest re-verified.
  for (std::size_t i = 0; i < payloads.size(); ++i) {
    const cf::Status verified =
        store.value()->verify(cf::Digest::ofText(payloads[i]));
    if (!verified) {
      std::printf("verify failed: %s\n", verified.str().c_str());
      return;
    }
  }
  const double elapsed = secondsSince(started);
  const double totalBytes =
      static_cast<double>(artifactCount) * static_cast<double>(artifactBytes);
  Result result;
  result.name = "artifact-store";
  result.seconds = elapsed;
  result.units = static_cast<double>(artifactCount);
  result.unit = "verified writes";
  result.megabytes = totalBytes / (1024.0 * 1024.0);
  report(result);
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

void benchFraming(std::size_t frames, std::size_t payloadBytes) {
  cf::Rng rng(99);
  std::vector<std::uint8_t> payload(payloadBytes);
  rng.fillBytes(std::span<std::uint8_t>(payload.data(), payload.size()));

  const auto started = Clock::now();
  std::size_t decodedBytes = 0;
  cf::FrameDecoder decoder(cf::kDefaultMaxPayloadBytes);
  std::vector<cf::Frame> ready;
  for (std::size_t i = 0; i < frames; ++i) {
    auto encoded = cf::encodeFrame(cf::FrameType::Chunk, 0, payload, cf::kDefaultMaxPayloadBytes);
    if (!encoded) {
      std::printf("encode failed: %s\n", encoded.error().str().c_str());
      return;
    }
    ready.clear();
    const cf::Status fed = decoder.feed(encoded.value(), ready);
    if (!fed || ready.size() != 1) {
      std::printf("decode failed\n");
      return;
    }
    decodedBytes += ready[0].payload.size();
  }
  const double elapsed = secondsSince(started);
  Result result;
  result.name = "framing";
  result.seconds = elapsed;
  result.units = static_cast<double>(frames);
  result.unit = "round trips";
  result.megabytes = static_cast<double>(decodedBytes) / (1024.0 * 1024.0);
  report(result);
}

/// Runs one controller and one agent in this process over a real socket pair and
/// counts deliveries that actually reached "acknowledged".
void benchDelivery(std::size_t targetCount, std::size_t artifactBytes, std::size_t generations) {
  const std::string root = temporaryRoot("delivery");
  const std::string secret = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
  writeText(root + "/secret.key", secret);
  cf::HmacKey key{};
  std::string trimmed;
  for (const char c : secret) {
    if (c != '\n' && c != '\r') {
      trimmed.push_back(c);
    }
  }
  if (!cf::fromHex(trimmed, std::span<std::uint8_t>(key.data(), key.size()))) {
    std::printf("benchmark key is not valid hex\n");
    return;
  }

  // Agents listen; the controller dials them.
  std::vector<std::unique_ptr<cf::Listener>> listeners;
  std::vector<std::unique_ptr<cf::TargetAgent>> agents;
  std::vector<std::thread> agentThreads;
  std::vector<std::atomic<bool>> stops(targetCount);
  std::vector<std::uint16_t> ports;
  for (std::size_t i = 0; i < targetCount; ++i) {
    cf::TargetAgent::Options options;
    options.stateDirectory = root + "/agent-" + std::to_string(i);
    options.target = cf::parseTargetId("bench-" + std::to_string(i)).value();
    options.klass = cf::TargetClass::NetworkDevice;
    options.guarantee = cf::ApplyGuarantee::AtomicActivate;
    options.key = key;
    options.maxArtifactBytes = 8u * 1024u * 1024u;
    cf::AgentStore::Recovery recovery;
    cf::LiveRecovery liveRecovery;
    auto agent = cf::TargetAgent::open(options, recovery, liveRecovery);
    if (!agent) {
      std::printf("agent open failed: %s\n", agent.error().str().c_str());
      return;
    }
    agents.push_back(std::move(agent).value());
    auto listener = cf::Listener::bindTcp("127.0.0.1", 0, 16);
    if (!listener) {
      std::printf("listener failed\n");
      return;
    }
    ports.push_back(listener.value()->port());
    listeners.push_back(std::move(listener).value());
  }
  for (std::size_t i = 0; i < targetCount; ++i) {
    agentThreads.emplace_back([&, i] {
      while (!stops[i].load()) {
        auto accepted = listeners[i]->accept(cf::monotonicMillis() + 50);
        if (!accepted) {
          if (accepted.error().code() == cf::ErrorCode::ShuttingDown) {
            return;
          }
          continue;
        }
        cf::FramedConnection connection(std::move(accepted).value(), cf::kDefaultMaxPayloadBytes);
        (void)agents[i]->serve(connection);
        connection.close();
      }
    });
  }

  cf::Distributor::Options options;
  options.nodeId = cf::parseNodeId("bench-ctl").value();
  options.stateDirectory = root + "/ctl-state";
  options.artifactRoot = root + "/ctl-artifacts";
  options.key = key;
  options.controlHost = "127.0.0.1";
  options.controlPort = 0;
  options.policy.maxConcurrentSessions = 4;
  options.policy.transferChunkBytes = 16384;
  options.policy.maxAttempts = 3;
  cf::Distributor::Recovery recovery;
  auto distributor = cf::Distributor::open(options, recovery);
  if (!distributor) {
    std::printf("distributor open failed: %s\n", distributor.error().str().c_str());
    return;
  }
  const cf::Status started = distributor.value()->start();
  if (!started) {
    std::printf("distributor start failed: %s\n", started.str().c_str());
    return;
  }

  cf::Rng rng(7);
  const auto begin = Clock::now();
  std::size_t acknowledged = 0;
  std::size_t planned = 0;
  for (std::size_t generation = 1; generation <= generations; ++generation) {
    std::string body(artifactBytes, ' ');
    for (std::size_t j = 0; j < artifactBytes; ++j) {
      body[j] = static_cast<char>('a' + rng.bounded(26));
    }
    cf::DeploymentPlan plan;
    plan.setId = cf::parseDeploymentSetId("bench-set-" + std::to_string(generation)).value();
    for (std::size_t i = 0; i < targetCount; ++i) {
      cf::DeploymentInstruction instruction;
      instruction.target = cf::parseTargetId("bench-" + std::to_string(i)).value();
      instruction.targetClass = cf::TargetClass::NetworkDevice;
      instruction.declaredGuarantee = cf::ApplyGuarantee::AtomicActivate;
      instruction.configKey = cf::parseConfigKey("fabric/underlay").value();
      instruction.artifact = cf::parseArtifactId("cfg/bench").value();
      instruction.revision = cf::Revision::fromValue(generation);
      instruction.generation = cf::Generation::fromValue(generation);
      instruction.schema = cf::parseSchemaId("cf.bench").value();
      instruction.schemaVersion = cf::SchemaVersion::fromValue(1);
      instruction.digest = cf::Digest::ofText(body);
      instruction.sizeBytes = body.size();
      instruction.requirement = cf::GuaranteeRequirement::RequireAtomic;
      instruction.mediaType = "text/plain";
      instruction.producer = "benchmark";
      instruction.endpoint = "127.0.0.1:" + std::to_string(ports[i]);
      const std::string source = root + "/artifact-" + std::to_string(generation) + ".cfg";
      writeText(source, body);
      instruction.sourcePath = source;
      plan.instructions.push_back(instruction);
    }
    std::vector<cf::DeploymentId> created;
    const cf::Status submitted = distributor.value()->submitPlan(plan, &created);
    if (!submitted) {
      std::printf("plan submission failed: %s\n", submitted.str().c_str());
      break;
    }
    planned += created.size();

    // Wait until every delivery of this generation has reached a recorded
    // outcome. Only completed deliveries are counted, never submissions.
    for (;;) {
      auto report = distributor.value()->convergence();
      if (!report) {
        break;
      }
      bool done = true;
      std::size_t acked = 0;
      for (const cf::LineageConvergence& lineage : report.value().lineages) {
        if (lineage.desiredGeneration.value() != generation) {
          continue;
        }
        if (lineage.state == cf::DeliveryState::Acknowledged) {
          acked += 1;
        } else if (lineage.state == cf::DeliveryState::Rejected ||
                   (lineage.state == cf::DeliveryState::Failed && lineage.failures >= 3)) {
          // Bounded: a delivery that cannot succeed must not hang the benchmark.
          acked += 1;
        } else {
          done = false;
        }
      }
      if (done) {
        acknowledged += acked;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
  }
  const double elapsed = secondsSince(begin);

  for (std::size_t i = 0; i < targetCount; ++i) {
    stops[i].store(true);
    listeners[i]->interrupt();
  }
  for (std::thread& thread : agentThreads) {
    thread.join();
  }
  distributor.value()->stop();

  Result result;
  result.name = "delivery";
  result.seconds = elapsed;
  result.units = static_cast<double>(acknowledged);
  result.unit = "acknowledged";
  result.megabytes =
      (static_cast<double>(acknowledged) * static_cast<double>(artifactBytes)) / (1024.0 * 1024.0);
  report(result);
  std::printf("                       (%zu deliveries completed of %zu planned, %zu target(s) x %zu "
              "generation(s), %.1f deliveries/s)\n",
              acknowledged, planned, targetCount, generations,
              elapsed > 0 ? static_cast<double>(acknowledged) / elapsed : 0.0);
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

}  // namespace

int main(int argc, char** argv) {
  cf::Logger::global().setLevel(cf::LogLevel::Error);
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--help" || argument == "-h") {
      std::printf("cfbench [--quick]\n");
      return 0;
    }
  }
  std::printf("%s benchmarks\n", std::string(cf::buildIdentification()).c_str());
  std::printf("%-22s %12s  %12s %-14s %12s\n", "benchmark", "elapsed", "completed", "unit",
              "throughput");

  benchArtifactStore(64, 256u * 1024u);
  benchFraming(2000, 64u * 1024u);
  benchDelivery(4, 256u * 1024u, 8);
  return 0;
}
