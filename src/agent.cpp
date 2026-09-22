// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/agent.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "cf/checked.hpp"
#include "cf/codec.hpp"
#include "cf/contract.hpp"
#include "cf/log.hpp"
#include "cf/protocol.hpp"
#include "cf/rng.hpp"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace cf {
namespace {

constexpr std::string_view kComponent = "agent";
constexpr std::size_t kMaxLiveValueBytes = 512;
constexpr std::size_t kArtifactCopyChunk = 256u * 1024u;
/// Durable transfer checkpoints. Between checkpoints the received byte count
/// advances in memory only. A restart then resumes from an earlier byte, which is
/// always safe because only the final digest authorises activation.
constexpr std::uint64_t kTransferCheckpointChunks = 16;

/// Terminates the process immediately, with no cleanup and no unwinding: the
/// same shape as a power loss. Only reachable through explicit fault injection.
[[noreturn]] void crashNow(int code) {
#if defined(_WIN32)
  ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(code));
#endif
  std::_Exit(code);
}

[[nodiscard]] std::string pointerText(Generation generation, const Digest& digest,
                                      const ArtifactId& artifact) {
  std::string text;
  text.append(std::to_string(generation.value()));
  text.push_back(' ');
  text.append(digest.hex());
  text.push_back(' ');
  text.append(artifact.str());
  text.push_back('\n');
  return text;
}

struct PointerValue {
  Generation generation;
  Digest digest;
  ArtifactId artifact;
};

[[nodiscard]] Result<PointerValue> parsePointer(std::string_view text) {
  const std::size_t firstSpace = text.find(' ');
  if (firstSpace == std::string_view::npos) {
    return Result<PointerValue>::fail(ErrorCode::MalformedInput, "live pointer is malformed");
  }
  const std::size_t secondSpace = text.find(' ', firstSpace + 1);
  if (secondSpace == std::string_view::npos) {
    return Result<PointerValue>::fail(ErrorCode::MalformedInput, "live pointer is malformed");
  }
  const std::string_view generationText = text.substr(0, firstSpace);
  const std::string_view digestText = text.substr(firstSpace + 1, secondSpace - firstSpace - 1);
  std::string_view artifactText = text.substr(secondSpace + 1);
  while (!artifactText.empty() &&
         (artifactText.back() == '\n' || artifactText.back() == '\r' || artifactText.back() == ' ')) {
    artifactText.remove_suffix(1);
  }
  PointerValue value;
  std::uint64_t generation = 0;
  for (const char c : generationText) {
    if (c < '0' || c > '9') {
      return Result<PointerValue>::fail(ErrorCode::MalformedInput,
                                        "live pointer generation is not a decimal integer");
    }
    const auto multiplied = checkedMul<std::uint64_t>(generation, 10u);
    if (!multiplied) {
      return Result<PointerValue>::fail(ErrorCode::ArithmeticOverflow,
                                        "live pointer generation overflowed");
    }
    const auto next = checkedAdd<std::uint64_t>(*multiplied, static_cast<std::uint64_t>(c - '0'));
    if (!next) {
      return Result<PointerValue>::fail(ErrorCode::ArithmeticOverflow,
                                        "live pointer generation overflowed");
    }
    generation = *next;
  }
  value.generation = Generation::fromValue(generation);
  CF_TRY_ASSIGN(value.digest, Digest::parse(digestText));
  if (!artifactText.empty()) {
    CF_TRY_ASSIGN(value.artifact, parseArtifactId(artifactText));
  }
  return Result<PointerValue>::ok(value);
}

[[nodiscard]] Result<std::string> readLiveValue(const std::string& path) {
  auto bytes = readFileBounded(path, kMaxLiveValueBytes);
  if (!bytes) {
    return Result<std::string>::fail(bytes.error());
  }
  return Result<std::string>::ok(
      std::string(reinterpret_cast<const char*>(bytes.value().data()), bytes.value().size()));
}

/// Streams src to dst through a temporary file and renames it into place. Never
/// leaves a partially written dst.
[[nodiscard]] Status copyFileAtomic(const std::string& source, const std::string& destination) {
  std::array<std::uint8_t, 16> suffix = secureRandom128();
  const std::string temporary =
      destination + ".part-" + toHex(std::span<const std::uint8_t>(suffix.data(), suffix.size()));
  std::FILE* in = std::fopen(source.c_str(), "rb");
  if (in == nullptr) {
    return Status::fail(ErrorCode::ArtifactUnavailable, "cannot open the source file", source);
  }
  std::FILE* out = std::fopen(temporary.c_str(), "wb");
  if (out == nullptr) {
    std::fclose(in);
    return Status::fail(ErrorCode::OpenFailed, "cannot create the destination file", temporary);
  }
  std::vector<std::uint8_t> buffer(kArtifactCopyChunk);
  Status result = Status::ok();
  for (;;) {
    const std::size_t read = std::fread(buffer.data(), 1, buffer.size(), in);
    if (read == 0) {
      if (std::ferror(in) != 0) {
        result = Status::fail(ErrorCode::IoFailure, "read error while copying", source);
      }
      break;
    }
    if (std::fwrite(buffer.data(), 1, read, out) != read) {
      result = Status::fail(ErrorCode::IoFailure, "write error while copying", temporary);
      break;
    }
  }
  std::fclose(in);
  const Status flushed = flushFileToDisk(out);
  std::fclose(out);
  if (!result) {
    std::error_code removed;
    std::filesystem::remove(temporary, removed);
    return result;
  }
  if (!flushed) {
    std::error_code removed;
    std::filesystem::remove(temporary, removed);
    return flushed;
  }
  std::error_code ec;
  std::filesystem::rename(temporary, destination, ec);
  if (ec) {
    std::error_code removed;
    std::filesystem::remove(temporary, removed);
    return Status::fail(ErrorCode::IoFailure, "cannot move the copied file into place", destination);
  }
  return Status::ok();
}

[[nodiscard]] std::vector<std::uint8_t> rollbackPayload(const AgentState& state) {
  ByteWriter writer(64);
  writer.u64(state.applyRollbacks);
  writer.u64(state.duplicatesSuppressed);
  writer.u64(state.staleOffersRefused);
  writer.u64(state.digestRejections);
  return writer.take();
}

}  // namespace

// --- FaultPlan -------------------------------------------------------------

Result<fault::FaultPlan> fault::FaultPlan::parse(std::string_view text) {
  FaultPlan plan;
  if (text.empty()) {
    return Result<FaultPlan>::ok(std::move(plan));
  }
  const std::array<std::string_view, 14> known = {
      fault::kAfterOffer,       fault::kAfterChunk,       fault::kAfterVerify,
      fault::kAfterStage,       fault::kAfterPrepare,     fault::kBeforeCommit,
      fault::kAfterCommit,      fault::kWithholdAck,      fault::kCorruptChunk,
      fault::kTruncateTransfer, fault::kDropAfterPrepare, fault::kStaleCommit,
      fault::kDuplicateChunk,   fault::kOversizeDeclare};

  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t comma = text.find(',', start);
    std::string_view entry =
        (comma == std::string_view::npos) ? text.substr(start) : text.substr(start, comma - start);
    while (!entry.empty() && entry.front() == ' ') {
      entry.remove_prefix(1);
    }
    while (!entry.empty() && entry.back() == ' ') {
      entry.remove_suffix(1);
    }
    if (!entry.empty()) {
      Entry parsed;
      const std::size_t colon = entry.find(':');
      const std::string_view name =
          (colon == std::string_view::npos) ? entry : entry.substr(0, colon);
      if (colon != std::string_view::npos) {
        const std::string_view countText = entry.substr(colon + 1);
        std::uint32_t count = 0;
        if (countText.empty()) {
          return Result<FaultPlan>::fail(ErrorCode::InvalidArgument,
                                         "fault injection count is missing", std::string(entry));
        }
        for (const char c : countText) {
          if (c < '0' || c > '9') {
            return Result<FaultPlan>::fail(ErrorCode::InvalidArgument,
                                           "fault injection count is not a decimal integer",
                                           std::string(entry));
          }
          const auto multiplied = checkedMul<std::uint32_t>(count, 10u);
          if (!multiplied) {
            return Result<FaultPlan>::fail(ErrorCode::ArithmeticOverflow,
                                           "fault injection count overflowed");
          }
          const auto next = checkedAdd<std::uint32_t>(*multiplied,
                                                      static_cast<std::uint32_t>(c - '0'));
          if (!next) {
            return Result<FaultPlan>::fail(ErrorCode::ArithmeticOverflow,
                                           "fault injection count overflowed");
          }
          count = *next;
        }
        parsed.count = count;
      }
      bool matched = false;
      for (const std::string_view candidate : known) {
        if (candidate == name) {
          matched = true;
          break;
        }
      }
      if (!matched) {
        return Result<FaultPlan>::fail(ErrorCode::InvalidArgument,
                                       "unknown fault injection point", std::string(name));
      }
      parsed.name.assign(name);
      plan.points_.push_back(std::move(parsed));
    }
    if (comma == std::string_view::npos) {
      break;
    }
    start = comma + 1;
  }
  return Result<FaultPlan>::ok(std::move(plan));
}

bool fault::FaultPlan::armed(std::string_view point) const {
  for (const Entry& entry : points_) {
    if (entry.name == point) {
      return true;
    }
  }
  return false;
}

std::uint32_t fault::FaultPlan::countFor(std::string_view point) const {
  for (const Entry& entry : points_) {
    if (entry.name == point) {
      return entry.count;
    }
  }
  return 0;
}

std::string fault::FaultPlan::render() const {
  std::string out;
  for (const Entry& entry : points_) {
    if (!out.empty()) {
      out.push_back(',');
    }
    out.append(entry.name);
    if (entry.count != 0) {
      out.push_back(':');
      out.append(std::to_string(entry.count));
    }
  }
  return out.empty() ? std::string("none") : out;
}

// --- TargetAgent -----------------------------------------------------------

TargetAgent::~TargetAgent() = default;

std::string TargetAgent::liveKeyDirectory(const ConfigKey& key) const {
  return liveRoot_ + "/" + key.str();
}

std::string TargetAgent::stagingPath(const DeploymentId& deployment) const {
  return stagingRoot_ + "/" + deployment.str() + ".part";
}

Result<std::unique_ptr<TargetAgent>> TargetAgent::open(const Options& options,
                                                       AgentStore::Recovery& recovery,
                                                       LiveRecovery& liveRecovery) {
  if (options.stateDirectory.empty()) {
    return Result<std::unique_ptr<TargetAgent>>::fail(ErrorCode::InvalidArgument,
                                                      "agent state directory must not be empty");
  }
  if (!options.target.isSet()) {
    return Result<std::unique_ptr<TargetAgent>>::fail(ErrorCode::InvalidArgument,
                                                      "agent target id must be set");
  }
  if (options.maxArtifactBytes == 0 || options.retainedPayloadsPerKey == 0) {
    return Result<std::unique_ptr<TargetAgent>>::fail(ErrorCode::InvalidArgument,
                                                      "agent bounds must be non-zero");
  }

  std::unique_ptr<TargetAgent> agent(new TargetAgent());
  agent->options_ = options;
  agent->liveRoot_ =
      options.liveDirectory.empty() ? (options.stateDirectory + "/live") : options.liveDirectory;
  agent->stagingRoot_ = options.stateDirectory + "/staging";

  std::error_code ec;
  std::filesystem::create_directories(agent->liveRoot_, ec);
  if (ec) {
    return Result<std::unique_ptr<TargetAgent>>::fail(ErrorCode::OpenFailed,
                                                      "cannot create the live configuration area",
                                                      agent->liveRoot_);
  }
  std::filesystem::create_directories(agent->stagingRoot_, ec);
  if (ec) {
    return Result<std::unique_ptr<TargetAgent>>::fail(ErrorCode::OpenFailed,
                                                      "cannot create the staging area",
                                                      agent->stagingRoot_);
  }

  AgentStore::Options storeOptions;
  storeOptions.directory = options.stateDirectory;
  storeOptions.name = "agent";
  auto store = AgentStore::open(storeOptions, recovery);
  if (!store) {
    return Result<std::unique_ptr<TargetAgent>>::fail(store.error());
  }
  agent->store_ = std::move(store).value();

  AgentState& state = agent->store_->state();
  if (state.target.isSet() && !(state.target == options.target)) {
    return Result<std::unique_ptr<TargetAgent>>::fail(
        ErrorCode::Conflict, "durable agent state belongs to a different target",
        state.target.str() + " != " + options.target.str());
  }
  if (state.term.isSet()) {
    if (state.klass != options.klass) {
      return Result<std::unique_ptr<TargetAgent>>::fail(
          ErrorCode::Conflict, "durable agent state declares a different target class");
    }
    if (state.guarantee != options.guarantee) {
      return Result<std::unique_ptr<TargetAgent>>::fail(
          ErrorCode::GuaranteeUnsupported,
          "durable agent state declares a different apply guarantee; changing it would silently "
          "change what activation means for this target");
    }
  }

  const auto nextTerm = checkedAdd<std::uint64_t>(state.term.value(), 1u);
  if (!nextTerm) {
    return Result<std::unique_ptr<TargetAgent>>::fail(ErrorCode::ArithmeticOverflow,
                                                      "agent term exhausted");
  }
  const auto nextRestarts = checkedAdd<std::uint32_t>(state.restartCount, 1u);
  if (!nextRestarts) {
    return Result<std::unique_ptr<TargetAgent>>::fail(ErrorCode::ArithmeticOverflow,
                                                      "agent restart counter exhausted");
  }

  ByteWriter identity(192);
  identity.string(options.target.str(), kMaxIdentifierLength);
  identity.u8(static_cast<std::uint8_t>(options.klass));
  identity.u8(static_cast<std::uint8_t>(options.guarantee));
  identity.u64(*nextTerm);
  identity.opaque128(secureRandom128());
  identity.u32(*nextRestarts);
  CF_TRY(agent->store_->commit(JournalRecordType::AgentIdentity, identity.span()));

  CF_TRY(agent->recoverLiveArea(liveRecovery));
  CF_TRY(agent->store_->compactIfNeeded());
  return Result<std::unique_ptr<TargetAgent>>::ok(std::move(agent));
}

Status TargetAgent::note(std::string_view text) {
  if (text.size() > kMaxNoteBytes) {
    return Status::fail(ErrorCode::LimitExceeded, "note exceeds its bound");
  }
  ByteWriter writer(64 + text.size());
  writer.string(text, kMaxNoteBytes);
  return store_->commit(JournalRecordType::Note, writer.span());
}

Status TargetAgent::recordNote(std::string_view text) { return note(text); }

Status TargetAgent::recoverLiveArea(LiveRecovery& recovery) {
  AgentState& state = store_->state();
  std::error_code ec;

  // 1. Partial transfers are kept only when the bytes on disk can support the
  //    recorded resume point.
  {
    std::vector<std::string> known;
    known.reserve(state.transfers.size());
    for (const auto& entry : state.transfers) {
      known.push_back(entry.first.str());
    }
    for (const auto& entry : std::filesystem::directory_iterator(stagingRoot_, ec)) {
      if (ec) {
        break;
      }
      if (!entry.is_regular_file(ec)) {
        continue;
      }
      const std::string name = entry.path().filename().string();
      const std::size_t dot = name.find(".part");
      const std::string stem = (dot == std::string::npos) ? name : name.substr(0, dot);
      if (std::find(known.begin(), known.end(), stem) != known.end()) {
        continue;
      }
      std::error_code removed;
      if (std::filesystem::remove(entry.path(), removed)) {
        recovery.removedStagingFiles += 1;
      }
    }
  }

  std::vector<DeploymentId> discard;
  std::vector<TransferRecord> resized;
  for (const auto& entry : state.transfers) {
    const TransferRecord& record = entry.second;
    const std::string path = stagingPath(record.deployment);
    std::error_code sizeError;
    const std::uintmax_t onDisk = std::filesystem::file_size(path, sizeError);
    if (sizeError) {
      discard.push_back(record.deployment);
      continue;
    }
    if (static_cast<std::uint64_t>(onDisk) < record.bytesReceived) {
      discard.push_back(record.deployment);
      continue;
    }
    if (static_cast<std::uint64_t>(onDisk) > record.bytesReceived) {
      std::error_code resizeError;
      std::filesystem::resize_file(path, record.bytesReceived, resizeError);
      if (resizeError) {
        discard.push_back(record.deployment);
        continue;
      }
      resized.push_back(record);
    }
  }
  for (const DeploymentId& deployment : discard) {
    recovery.detail.append("discarded-transfer=");
    recovery.detail.append(deployment.str());
    recovery.detail.push_back(' ');
    CF_TRY(destroyTransfer(deployment, "on-disk bytes cannot support the recorded resume point"));
  }
  for (const TransferRecord& record : resized) {
    CF_TRY(checkpointTransfer(record));
  }

  // 2. The live pointer is the authority for what is activated. Durable state is
  //    reconciled to it, in either direction, and the resolution is recorded.
  for (const auto& entry : std::filesystem::directory_iterator(liveRoot_, ec)) {
    if (ec) {
      break;
    }
    if (!entry.is_directory(ec)) {
      continue;
    }
    const std::string directory = entry.path().string();
    const std::string currentPath = directory + "/current";
    const std::string pendingPath = directory + "/pending";

    const bool pendingPresent = std::filesystem::exists(pendingPath, ec);
    auto pointer = readLiveValue(currentPath);
    const bool pointerPresent = static_cast<bool>(pointer);

    Generation liveGeneration;
    Digest liveDigest;
    ArtifactId liveArtifact;
    bool usable = false;
    if (pointerPresent) {
      auto parsed = parsePointer(pointer.value());
      if (parsed) {
        liveGeneration = parsed.value().generation;
        liveDigest = parsed.value().digest;
        liveArtifact = parsed.value().artifact;
        usable = true;
      } else {
        std::error_code removed;
        std::filesystem::remove(currentPath, removed);
        recovery.clearedUnverifiableCommit = true;
        recovery.detail.append("unreadable-live-pointer=");
        recovery.detail.append(directory);
        recovery.detail.push_back(' ');
      }
    }

    if (pendingPresent) {
      if (usable && liveGeneration == state.preparedGeneration &&
          liveDigest == state.preparedDigest) {
        // The switch completed; only the resolve record is missing.
        recovery.adoptedCompletedSwitch = true;
      } else {
        recovery.rolledBackUnresolvedPrepare = true;
        state.applyRollbacks += 1;
        CF_TRY(store_->commit(JournalRecordType::AgentRollbackNote, rollbackPayload(state)));
      }
      std::error_code removed;
      std::filesystem::remove(pendingPath, removed);
      recovery.detail.append("resolved-prepare-window=");
      recovery.detail.append(directory);
      recovery.detail.push_back(' ');
    }

    if (usable) {
      const std::string payloadPath = directory + "/payload/" +
                                      std::to_string(liveGeneration.value()) + "-" +
                                      liveDigest.hex().substr(0, 12) + ".cfg";
      bool verified = true;
      if (options_.verifyCommittedPayloadOnStart) {
        auto actual = hashStagingFile(payloadPath, 0);
        verified = actual && (actual.value() == liveDigest);
        recovery.verifiedPayloads += 1;
      }
      const bool alreadyCommitted =
          (liveGeneration == state.committedGeneration) &&
          (liveDigest == state.committedDigest) && state.committedGeneration.isSet();
      if (!verified) {
        recovery.clearedUnverifiableCommit = true;
        recovery.detail.append("unverifiable-payload=");
        recovery.detail.append(payloadPath);
        recovery.detail.push_back(' ');
        ByteWriter cleared(96);
        cleared.u64(0);
        cleared.digest(Digest{});
        cleared.string(std::string(), kMaxIdentifierLength);
        CF_TRY(store_->commit(JournalRecordType::AgentTargetCommit, cleared.span()));
      } else if (!alreadyCommitted) {
        recovery.adoptedCompletedSwitch = true;
        recovery.detail.append("adopted-live-pointer=");
        recovery.detail.append(directory);
        recovery.detail.push_back(' ');
        ByteWriter adopted(160);
        adopted.u64(liveGeneration.value());
        adopted.digest(liveDigest);
        adopted.string(liveArtifact.str(), kMaxIdentifierLength);
        CF_TRY(store_->commit(JournalRecordType::AgentTargetCommit, adopted.span()));
      }
    } else if (state.committedGeneration.isSet()) {
      // Nothing is activated, so claiming a committed generation would be a
      // claim this target cannot support.
      recovery.clearedUnverifiableCommit = true;
      recovery.detail.append("missing-live-pointer=");
      recovery.detail.append(directory);
      recovery.detail.push_back(' ');
      ByteWriter cleared(96);
      cleared.u64(0);
      cleared.digest(Digest{});
      cleared.string(std::string(), kMaxIdentifierLength);
      CF_TRY(store_->commit(JournalRecordType::AgentTargetCommit, cleared.span()));
    }
  }

  // 3. A durable prepare marker with no live area behind it is resolved as an
  //    abort, and reported.
  if (state.applyPrepared) {
    recovery.rolledBackUnresolvedPrepare = true;
    state.applyRollbacks += 1;
    CF_TRY(store_->commit(JournalRecordType::AgentRollbackNote, rollbackPayload(state)));
    ByteWriter resolved(32);
    resolved.u64(state.activations);
    CF_TRY(store_->commit(JournalRecordType::AgentApplyResolved, resolved.span()));
  }

  if (recovery.rolledBackUnresolvedPrepare || recovery.adoptedCompletedSwitch ||
      recovery.clearedUnverifiableCommit || recovery.removedStagingFiles > 0) {
    std::string message = "live-area recovery:";
    if (recovery.rolledBackUnresolvedPrepare) {
      message.append(" aborted-unresolved-prepare");
    }
    if (recovery.adoptedCompletedSwitch) {
      message.append(" adopted-completed-switch");
    }
    if (recovery.clearedUnverifiableCommit) {
      message.append(" cleared-unverifiable-commit");
    }
    if (recovery.removedStagingFiles > 0) {
      message.append(" removed-staging=");
      message.append(std::to_string(recovery.removedStagingFiles));
    }
    Logger::global().warn(kComponent, message);
  }
  return Status::ok();
}

Status TargetAgent::prunePayloads(const ConfigKey& key) {
  const std::string payloadDirectory = liveKeyDirectory(key) + "/payload";
  std::error_code ec;
  std::vector<std::pair<std::string, std::int64_t>> entries;
  for (const auto& entry : std::filesystem::directory_iterator(payloadDirectory, ec)) {
    if (ec) {
      return Status::ok();
    }
    if (!entry.is_regular_file(ec)) {
      continue;
    }
    std::error_code timeError;
    const auto stamp = std::filesystem::last_write_time(entry.path(), timeError);
    if (timeError) {
      continue;
    }
    entries.emplace_back(entry.path().string(),
                         static_cast<std::int64_t>(stamp.time_since_epoch().count()));
  }
  if (entries.size() <= options_.retainedPayloadsPerKey) {
    return Status::ok();
  }
  std::sort(entries.begin(), entries.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.second > rhs.second; });
  for (std::size_t i = options_.retainedPayloadsPerKey; i < entries.size(); ++i) {
    std::error_code removed;
    std::filesystem::remove(entries[i].first, removed);
  }
  return Status::ok();
}

Result<Digest> TargetAgent::hashStagingFile(const std::string& path, std::uint64_t expectedBytes) {
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return Result<Digest>::fail(ErrorCode::ArtifactUnavailable,
                                "artifact file is not readable", path);
  }
  Sha256 hasher;
  std::vector<std::uint8_t> buffer(64u * 1024u);
  std::uint64_t total = 0;
  for (;;) {
    const std::size_t read = std::fread(buffer.data(), 1, buffer.size(), file);
    if (read == 0) {
      break;
    }
    hasher.update(std::span<const std::uint8_t>(buffer.data(), read));
    const auto next = checkedAdd<std::uint64_t>(total, static_cast<std::uint64_t>(read));
    if (!next) {
      std::fclose(file);
      return Result<Digest>::fail(ErrorCode::ArithmeticOverflow, "artifact size overflowed");
    }
    total = *next;
  }
  const bool ioError = std::ferror(file) != 0;
  std::fclose(file);
  if (ioError) {
    return Result<Digest>::fail(ErrorCode::IoFailure, "read error while hashing artifact", path);
  }
  if (expectedBytes != 0 && total != expectedBytes) {
    return Result<Digest>::fail(ErrorCode::SizeMismatch,
                                "artifact size does not match the declaration",
                                std::to_string(total) + " != " + std::to_string(expectedBytes));
  }
  return Result<Digest>::ok(Digest::fromBytes(hasher.finish()));
}

Result<TargetAgent::LivePointer> TargetAgent::readLivePointer(const ConfigKey& key) const {
  const std::string path = liveKeyDirectory(key) + "/current";
  auto text = readLiveValue(path);
  if (!text) {
    return Result<LivePointer>::ok(LivePointer{});
  }
  auto parsed = parsePointer(text.value());
  if (!parsed) {
    return Result<LivePointer>::fail(parsed.error());
  }
  LivePointer pointer;
  pointer.present = true;
  pointer.generation = parsed.value().generation;
  pointer.digest = parsed.value().digest;
  return Result<LivePointer>::ok(pointer);
}

Status TargetAgent::checkpointTransfer(const TransferRecord& record) {
  ByteWriter writer(288);
  writer.string(record.deployment.str(), kMaxIdentifierLength);
  writer.u64(record.stream.value());
  writer.string(record.key.str(), kMaxIdentifierLength);
  writer.string(record.artifact.str(), kMaxIdentifierLength);
  writer.u64(record.generation.value());
  writer.digest(record.digest);
  writer.u64(record.totalBytes);
  writer.u64(record.bytesReceived);
  writer.boolean(record.verified);
  writer.boolean(record.staged);
  writer.i64(record.updatedAtMillis);
  return store_->commit(JournalRecordType::AgentTransferUpsert, writer.span());
}

Status TargetAgent::destroyTransfer(const DeploymentId& deployment, std::string_view why) {
  std::error_code removed;
  std::filesystem::remove(stagingPath(deployment), removed);
  if (store_->state().transfers.find(deployment) == store_->state().transfers.end()) {
    return Status::ok();
  }
  ByteWriter writer(128);
  writer.string(deployment.str(), kMaxIdentifierLength);
  CF_TRY(store_->commit(JournalRecordType::AgentTransferRemove, writer.span()));
  Logger::global().debug(kComponent,
                         "discarded transfer " + deployment.str() + ": " + std::string(why));
  return Status::ok();
}

Status TargetAgent::beginTransfer(const PrepareMessage& message, std::uint64_t resumeFrom,
                                  StreamId* stream) {
  TransferRecord record;
  record.deployment = message.deployment;
  record.stream = message.stream;
  record.key = message.key;
  record.artifact = message.artifact;
  record.generation = message.generation;
  record.digest = message.digest;
  record.totalBytes = message.sizeBytes;
  record.bytesReceived = resumeFrom;
  record.verified = false;
  record.staged = false;
  record.updatedAtMillis = nowUnixMillis();
  if (stream != nullptr) {
    *stream = record.stream;
  }
  return checkpointTransfer(record);
}

// --- Session ---------------------------------------------------------------

Status TargetAgent::serve(FramedConnection& connection) {
  Session session;
  session.connection = &connection;
  session.peerMaxPayload = kDefaultMaxPayloadBytes;

  const Status handshakeStatus = handshake(session);
  if (!handshakeStatus) {
    Logger::global().warn(kComponent, "session rejected: " + handshakeStatus.str());
    return handshakeStatus;
  }
  Logger::global().info(kComponent, "session established with " + session.authorityNode.str() +
                                        " epoch=" + std::to_string(session.authorityEpoch.value()) +
                                        " incarnation=" +
                                        session.authorityIncarnation.hex().substr(0, 8));

  for (;;) {
    const std::int64_t deadline = monotonicMillis() + options_.sessionIdleTimeoutMillis;
    auto frame = connection.receive(deadline);
    if (!frame) {
      if (frame.error().code() == ErrorCode::PeerIdleTimeout) {
        Logger::global().info(kComponent, "session idle timeout; closing");
        return Status::ok();
      }
      if (frame.error().code() == ErrorCode::ConnectionClosed) {
        return Status::ok();
      }
      return Status::fail(frame.error());
    }
    bool keepGoing = true;
    const Status handled = dispatch(session, frame.value(), &keepGoing);
    if (!handled) {
      Logger::global().warn(kComponent, "session error while handling " +
                                            std::string(frameTypeName(frame.value().type())) + ": " +
                                            handled.str());
      return handled;
    }
    if (!keepGoing) {
      return Status::ok();
    }
  }
}

Status TargetAgent::handshake(Session& session) {
  const std::int64_t deadline = monotonicMillis() + options_.sessionIdleTimeoutMillis;
  auto frame = session.connection->receive(deadline);
  if (!frame) {
    return Status::fail(frame.error());
  }
  if (frame.value().type() != FrameType::Hello) {
    return Status::fail(ErrorCode::UnexpectedMessage, "expected a hello frame",
                        std::string(frameTypeName(frame.value().type())));
  }
  CF_TRY_ASSIGN(const HelloMessage hello, decodeHello(frame.value().payload));

  const auto refuse = [&](ErrorCode code, std::string detail) -> Status {
    AuthRejectMessage reject;
    reject.code = code;
    reject.detail = std::move(detail);
    auto encoded = encodeAuthReject(reject);
    if (encoded) {
      (void)session.connection->send(FrameType::AuthReject, kFrameFlagResponse, encoded.value(),
                                     monotonicMillis() + options_.sessionIdleTimeoutMillis);
    }
    return Status::fail(code, reject.detail);
  };

  if (hello.minWireVersion > kWireVersion || hello.maxWireVersion < kWireVersion) {
    return refuse(ErrorCode::UnsupportedVersion, "no mutually supported wire version");
  }
  if (options_.authenticate) {
    const Status authenticated = verifyAuthenticated(frame.value().payload, options_.key);
    if (!authenticated) {
      return refuse(ErrorCode::Unauthenticated, "peer authentication tag did not verify");
    }
  }

  AgentState& state = store_->state();
  if (state.lastControllerEpoch.isSet()) {
    if (hello.epoch < state.lastControllerEpoch) {
      return refuse(ErrorCode::StaleEpoch,
                    "controller authority epoch is older than the accepted one: " +
                        std::to_string(hello.epoch.value()) + " < " +
                        std::to_string(state.lastControllerEpoch.value()));
    }
    if (hello.epoch == state.lastControllerEpoch && state.lastControllerIncarnation.isSet() &&
        !(hello.incarnation == state.lastControllerIncarnation)) {
      return refuse(ErrorCode::FencedIncarnation,
                    "a different controller incarnation claims an already accepted epoch");
    }
  }

  // The authority is adopted durably before anything it sends can change state.
  ByteWriter fence(192);
  fence.u64(hello.epoch.value());
  fence.opaque128(hello.incarnation.bytes());
  fence.string(hello.nodeId.str(), kMaxIdentifierLength);
  CF_TRY(store_->commit(JournalRecordType::AgentControllerFence, fence.span()));
  session.authorityEpoch = hello.epoch;
  session.authorityIncarnation = hello.incarnation;
  session.authorityNode = hello.nodeId;
  session.peerMaxPayload = std::min(hello.maxPayloadBytes, kAbsoluteMaxPayloadBytes);

  HelloAckMessage ack;
  ack.wireVersion = kWireVersion;
  ack.target = state.target;
  ack.targetClass = state.klass;
  ack.guarantee = state.guarantee;
  ack.term = state.term;
  ack.incarnation = state.incarnation;
  ack.nonce = SessionNonce(secureRandom128());
  ack.maxPayloadBytes = kDefaultMaxPayloadBytes;
  ack.capabilities = capabilitiesFor(state.guarantee);
  ack.committedGeneration = state.committedGeneration;
  ack.committedDigest = state.committedDigest;
  ack.committedArtifact = state.committedArtifact;
  ack.restartCount = state.restartCount;
  CF_TRY_ASSIGN(std::vector<std::uint8_t> encoded, encodeHelloAck(ack));
  if (options_.authenticate) {
    CF_TRY(sealAuthenticated(encoded, options_.key));
  }
  CF_TRY(session.connection->send(FrameType::HelloAck, kFrameFlagResponse, encoded, deadline));

  auto confirmFrame = session.connection->receive(deadline);
  if (!confirmFrame) {
    return Status::fail(confirmFrame.error());
  }
  if (confirmFrame.value().type() != FrameType::HelloConfirm) {
    return Status::fail(ErrorCode::UnexpectedMessage, "expected a hello-confirm frame",
                        std::string(frameTypeName(confirmFrame.value().type())));
  }
  CF_TRY_ASSIGN(const HelloConfirmMessage confirm,
                decodeHelloConfirm(confirmFrame.value().payload));
  if (options_.authenticate) {
    // The controller's confirmation must be the tag over the exact ack payload
    // this process produced, which binds the session to this incarnation.
    std::vector<std::uint8_t> expected = encoded;
    std::copy(confirm.authTag.begin(), confirm.authTag.end(),
              expected.begin() + static_cast<std::ptrdiff_t>(expected.size() - kAuthTagBytes));
    const Status verified = verifyAuthenticated(expected, options_.key);
    if (!verified) {
      return refuse(ErrorCode::Unauthenticated,
                    "controller failed to confirm the session transcript");
    }
  } else {
    // Without authentication the confirmation is meaningless; a zero tag is all
    // that is accepted and the degraded guarantee is reported at start-up.
    for (const std::uint8_t byte : confirm.authTag) {
      if (byte != 0) {
        return refuse(ErrorCode::Unauthenticated,
                      "authentication is disabled but the controller sent a tag");
      }
    }
  }
  return Status::ok();
}

Status TargetAgent::dispatch(Session& session, const Frame& frame, bool* keepGoing) {
  switch (frame.type()) {
    case FrameType::Prepare:
      return onPrepare(session, frame.payload);
    case FrameType::Chunk:
      return onChunk(session, frame.payload);
    case FrameType::TransferComplete:
      return onTransferComplete(session, frame.payload);
    case FrameType::Stage:
      return onStage(session, frame.payload);
    case FrameType::ApplyPrepare:
      return onApplyPrepare(session, frame.payload);
    case FrameType::ApplyCommit:
      return onApplyCommit(session, frame.payload);
    case FrameType::ApplyAbort:
      return onApplyAbort(session, frame.payload);
    case FrameType::ReconcileRequest:
      return onReconcileRequest(session, frame.payload);
    case FrameType::Retire:
      return onRetire(session, frame.payload);
    case FrameType::Ping:
      return onPing(session, frame.payload);
    case FrameType::Goodbye: {
      CF_TRY_ASSIGN(const GoodbyeMessage goodbye, decodeGoodbye(frame.payload));
      Logger::global().info(kComponent, "peer said goodbye: " + std::string(errorCodeName(goodbye.code)) +
                                            " " + goodbye.reason);
      *keepGoing = false;
      return Status::ok();
    }
    default:
      return Status::fail(ErrorCode::UnexpectedMessage, "message is not valid on an agent session",
                          std::string(frameTypeName(frame.type())));
  }
}

Status TargetAgent::sendNack(Session& session, const DeploymentId& deployment, const ConfigKey& key,
                             Generation generation, const Digest& digest, ErrorCode code,
                             std::string detail) {
  AgentState& state = store_->state();
  DeliveryNackMessage nack;
  nack.deployment = deployment;
  nack.key = key;
  nack.generation = generation.isSet() ? generation : Generation::fromValue(1);
  nack.digest = digest.isSet() ? digest : Digest::ofText("no-digest");
  nack.code = code;
  nack.directive = retryDirectiveFor(code);
  nack.term = state.term;
  nack.incarnation = state.incarnation;
  nack.detail = std::move(detail);
  if (nack.detail.size() > kMaxMessageDetailBytes) {
    nack.detail.resize(kMaxMessageDetailBytes);
  }
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodeDeliveryNack(nack));
  return session.connection->send(FrameType::DeliveryNack, 0, encoded,
                                  monotonicMillis() + options_.sessionIdleTimeoutMillis);
}

Status TargetAgent::sendAck(Session& session, const DeploymentId& deployment, const ConfigKey& key,
                            Generation generation, const Digest& digest, DeliveryState state,
                            std::uint64_t bytesTransferred, bool fromReconcile) {
  if (options_.faults.armed(fault::kWithholdAck)) {
    Logger::global().warn(kComponent,
                          "fault injection: withholding the acknowledgement for " +
                              deployment.str());
    return Status::ok();
  }
  AgentState& agentState = store_->state();
  DeliveryAckMessage ack;
  ack.deployment = deployment;
  ack.key = key;
  ack.generation = generation;
  ack.digest = digest;
  ack.artifact = agentState.committedArtifact;
  ack.state = state;
  ack.term = agentState.term;
  ack.incarnation = agentState.incarnation;
  ack.authorityEpoch = session.authorityEpoch;
  ack.guarantee = agentState.guarantee;
  ack.bytesTransferred = bytesTransferred;
  ack.targetTimestampMillis = nowUnixMillis();
  ack.evidenceFromReconcile = fromReconcile;
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodeDeliveryAck(ack));
  return session.connection->send(FrameType::DeliveryAck, 0, encoded,
                                  monotonicMillis() + options_.sessionIdleTimeoutMillis);
}

Status TargetAgent::refusePrepare(Session& session, const PrepareMessage& message, ErrorCode code,
                                  std::string detail, DeliveryState observed) {
  PrepareRejectMessage reject;
  reject.deployment = message.deployment;
  reject.code = code;
  reject.detail = std::move(detail);
  if (reject.detail.size() > kMaxMessageDetailBytes) {
    reject.detail.resize(kMaxMessageDetailBytes);
  }
  reject.observedState = observed;
  reject.committedGeneration = store_->state().committedGeneration;
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodePrepareReject(reject));
  return session.connection->send(FrameType::PrepareReject, kFrameFlagResponse, encoded,
                                  monotonicMillis() + options_.sessionIdleTimeoutMillis);
}

Status TargetAgent::onPrepare(Session& session, std::span<const std::uint8_t> payload) {
  CF_TRY_ASSIGN(const PrepareMessage message, decodePrepare(payload));
  AgentState& state = store_->state();

  if (message.sizeBytes > options_.maxArtifactBytes) {
    return refusePrepare(session, message, ErrorCode::OversizePayload,
                         "artifact exceeds this target's size bound",
                         state.committedGeneration.isSet() ? DeliveryState::Applied
                                                           : DeliveryState::Prepared);
  }
  if (state.committedGeneration.isSet() && message.generation < state.committedGeneration) {
    state.staleOffersRefused += 1;
    CF_TRY(store_->commit(JournalRecordType::AgentRollbackNote, rollbackPayload(state)));
    return refusePrepare(session, message, ErrorCode::StaleGeneration,
                         "offered generation is older than the committed generation",
                         DeliveryState::Applied);
  }
  if (state.committedGeneration.isSet() && message.generation == state.committedGeneration &&
      !(message.digest == state.committedDigest)) {
    state.staleOffersRefused += 1;
    CF_TRY(store_->commit(JournalRecordType::AgentRollbackNote, rollbackPayload(state)));
    return refusePrepare(session, message, ErrorCode::GenerationConflict,
                         "a different content digest is already committed for this generation",
                         DeliveryState::Applied);
  }
  if (!guaranteeSatisfies(state.guarantee, message.requirement)) {
    return refusePrepare(session, message, ErrorCode::GuaranteeUnsupported,
                         std::string("target offers '") +
                             std::string(applyGuaranteeName(state.guarantee)) +
                             "' which cannot satisfy '" +
                             std::string(guaranteeRequirementName(message.requirement)) + "'",
                         DeliveryState::Prepared);
  }
  if (state.applyPrepared) {
    return refusePrepare(session, message, ErrorCode::Busy,
                         "an unresolved prepare window is open on this target",
                         DeliveryState::Staged);
  }

  PrepareAckMessage ack;
  ack.deployment = message.deployment;
  ack.stream = message.stream;
  ack.committedGeneration = state.committedGeneration;
  ack.committedDigest = state.committedDigest;
  ack.priorGeneration = state.committedGeneration;
  ack.priorDigest = state.committedDigest;
  ack.priorState =
      state.committedGeneration.isSet() ? DeliveryState::Applied : DeliveryState::Prepared;

  const AppliedFinding* finding = state.findFinding(message.key, message.digest);
  if (finding != nullptr && isActivationState(finding->state) &&
      finding->generation == message.generation) {
    ack.duplicateSuppressed = true;
    ack.priorState = finding->state;
    ack.priorGeneration = finding->generation;
    ack.priorDigest = finding->digest;
    ack.resumeFromOffset = message.sizeBytes;
    state.duplicatesSuppressed += 1;
    CF_TRY(store_->commit(JournalRecordType::AgentRollbackNote, rollbackPayload(state)));
    CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodePrepareAck(ack));
    CF_TRY(session.connection->send(FrameType::PrepareAck, kFrameFlagResponse, encoded,
                                    monotonicMillis() + options_.sessionIdleTimeoutMillis));
    return Status::ok();
  }

  std::uint64_t resumeFrom = 0;
  const auto existing = state.transfers.find(message.deployment);
  if (existing != state.transfers.end()) {
    const TransferRecord& record = existing->second;
    if (record.digest == message.digest && record.generation == message.generation &&
        record.totalBytes == message.sizeBytes && !record.verified) {
      std::error_code sizeError;
      const std::uintmax_t onDisk =
          std::filesystem::file_size(stagingPath(message.deployment), sizeError);
      if (!sizeError) {
        resumeFrom =
            std::min<std::uint64_t>(record.bytesReceived, static_cast<std::uint64_t>(onDisk));
      }
    } else {
      CF_TRY(destroyTransfer(message.deployment, "offer describes different content"));
    }
  }

  CF_TRY(beginTransfer(message, resumeFrom, nullptr));
  ack.resumeFromOffset = resumeFrom;
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodePrepareAck(ack));
  CF_TRY(session.connection->send(FrameType::PrepareAck, kFrameFlagResponse, encoded,
                                  monotonicMillis() + options_.sessionIdleTimeoutMillis));
  if (options_.faults.armed(fault::kAfterOffer)) {
    Logger::global().warn(kComponent, "fault injection: dying after offer");
    crashNow(71);
  }
  return Status::ok();
}

Status TargetAgent::onChunk(Session& session, std::span<const std::uint8_t> payload) {
  CF_TRY_ASSIGN(const ChunkMessage chunk, decodeChunk(payload));
  AgentState& state = store_->state();

  DeploymentId deployment;
  for (const auto& entry : state.transfers) {
    if (entry.second.stream == chunk.stream) {
      deployment = entry.first;
      break;
    }
  }
  const auto respond = [&](const ChunkAckMessage& ack) -> Status {
    auto encoded = encodeChunkAck(ack);
    if (!encoded) {
      return Status::fail(encoded.error());
    }
    return session.connection->send(FrameType::ChunkAck, kFrameFlagResponse, encoded.value(),
                                    monotonicMillis() + options_.sessionIdleTimeoutMillis);
  };

  if (!deployment.isSet()) {
    ChunkAckMessage ack;
    ack.stream = chunk.stream;
    ack.sequence = chunk.sequence;
    ack.code = ErrorCode::NotFound;
    ack.detail = "no transfer is open for this stream";
    return respond(ack);
  }

  const TransferRecord current = state.transfers[deployment];
  ChunkAckMessage ack;
  ack.stream = chunk.stream;
  ack.sequence = chunk.sequence;
  ack.bytesReceived = current.bytesReceived;

  if (chunk.offset != current.bytesReceived) {
    ack.code = ErrorCode::ReorderedFrame;
    ack.detail =
        chunk.offset < current.bytesReceived ? "duplicate chunk" : "chunk arrived out of order";
    return respond(ack);
  }
  const auto end =
      checkedAdd<std::uint64_t>(chunk.offset, static_cast<std::uint64_t>(chunk.data.size()));
  if (!end || *end > current.totalBytes) {
    ack.code = ErrorCode::SizeMismatch;
    ack.detail = "chunk would extend past the declared artifact size";
    return respond(ack);
  }

  std::vector<std::uint8_t> written = chunk.data;
  if (options_.faults.armed(fault::kCorruptChunk) && !written.empty()) {
    written[0] = static_cast<std::uint8_t>(written[0] ^ 0xFFu);
  }

  const std::string path = stagingPath(deployment);
  std::FILE* file = std::fopen(path.c_str(), current.bytesReceived == 0 ? "wb" : "r+b");
  if (file == nullptr) {
    ack.code = ErrorCode::IoFailure;
    ack.detail = "cannot open the staging file";
    return respond(ack);
  }
#if defined(_WIN32)
  const bool seekOk = _fseeki64(file, static_cast<__int64>(chunk.offset), SEEK_SET) == 0;
#else
  const bool seekOk = fseeko(file, static_cast<off_t>(chunk.offset), SEEK_SET) == 0;
#endif
  const std::size_t writtenBytes =
      (seekOk && !written.empty()) ? std::fwrite(written.data(), 1, written.size(), file) : 0;
  const bool flushFailed = std::fflush(file) != 0;
  std::fclose(file);
  if (!seekOk || writtenBytes != written.size() || flushFailed) {
    ack.code = ErrorCode::IoFailure;
    ack.detail = "cannot persist the chunk";
    return respond(ack);
  }

  TransferRecord updated = current;
  updated.bytesReceived = *end;
  updated.updatedAtMillis = nowUnixMillis();
  ack.bytesReceived = updated.bytesReceived;
  chunkCounter_ += 1;
  if (chunkCounter_ % kTransferCheckpointChunks == 0 || updated.bytesReceived == updated.totalBytes) {
    CF_TRY(checkpointTransfer(updated));
  } else {
    state.transfers[deployment] = updated;
  }

  const std::uint32_t injected = options_.faults.countFor(fault::kAfterChunk);
  if (injected != 0 && chunkCounter_ >= injected) {
    Logger::global().warn(kComponent,
                          "fault injection: dying after " + std::to_string(injected) + " chunk(s)");
    crashNow(72);
  }
  return respond(ack);
}

Status TargetAgent::onTransferComplete(Session& session, std::span<const std::uint8_t> payload) {
  CF_TRY_ASSIGN(const TransferCompleteMessage message, decodeTransferComplete(payload));
  AgentState& state = store_->state();

  TransferResultMessage result;
  result.deployment = message.deployment;
  result.stream = message.stream;

  const auto found = state.transfers.find(message.deployment);
  if (found == state.transfers.end()) {
    result.code = ErrorCode::NotFound;
    result.detail = "no transfer is open for this deployment";
    CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodeTransferResult(result));
    return session.connection->send(FrameType::TransferResult, kFrameFlagResponse, encoded,
                                    monotonicMillis() + options_.sessionIdleTimeoutMillis);
  }
  const TransferRecord current = found->second;
  result.bytesReceived = current.bytesReceived;

  if (current.bytesReceived != current.totalBytes) {
    result.code = ErrorCode::SizeMismatch;
    result.detail = "the transfer is incomplete at the target";
    CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodeTransferResult(result));
    return session.connection->send(FrameType::TransferResult, kFrameFlagResponse, encoded,
                                    monotonicMillis() + options_.sessionIdleTimeoutMillis);
  }
  if (!(message.digest == current.digest) || message.sizeBytes != current.totalBytes) {
    result.code = ErrorCode::Conflict;
    result.detail = "the completion message describes different content";
    CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodeTransferResult(result));
    return session.connection->send(FrameType::TransferResult, kFrameFlagResponse, encoded,
                                    monotonicMillis() + options_.sessionIdleTimeoutMillis);
  }

  auto actual = hashStagingFile(stagingPath(message.deployment), current.totalBytes);
  if (!actual || !(actual.value() == current.digest)) {
    state.digestRejections += 1;
    CF_TRY(store_->commit(JournalRecordType::AgentRollbackNote, rollbackPayload(state)));
    CF_TRY(destroyTransfer(message.deployment, "digest mismatch"));
    result.verified = false;
    result.code = actual ? ErrorCode::DigestMismatch : actual.error().code();
    result.detail = "the staged content does not hash to the declared digest";
    CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodeTransferResult(result));
    CF_TRY(session.connection->send(FrameType::TransferResult, kFrameFlagResponse, encoded,
                                    monotonicMillis() + options_.sessionIdleTimeoutMillis));
    return sendNack(session, message.deployment, current.key, current.generation, current.digest,
                    ErrorCode::DigestMismatch, "digest mismatch at the target");
  }

  TransferRecord verified = current;
  verified.verified = true;
  verified.updatedAtMillis = nowUnixMillis();
  CF_TRY(checkpointTransfer(verified));

  result.verified = true;
  result.code = ErrorCode::Ok;
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodeTransferResult(result));
  CF_TRY(session.connection->send(FrameType::TransferResult, kFrameFlagResponse, encoded,
                                  monotonicMillis() + options_.sessionIdleTimeoutMillis));
  if (options_.faults.armed(fault::kAfterVerify)) {
    Logger::global().warn(kComponent, "fault injection: dying after verification");
    crashNow(73);
  }
  return Status::ok();
}

Status TargetAgent::onStage(Session& session, std::span<const std::uint8_t> payload) {
  CF_TRY_ASSIGN(const StageMessage message, decodeStage(payload));
  AgentState& state = store_->state();

  StageAckMessage ack;
  ack.deployment = message.deployment;
  const auto respond = [&]() -> Status {
    auto encoded = encodeStageAck(ack);
    if (!encoded) {
      return Status::fail(encoded.error());
    }
    return session.connection->send(FrameType::StageAck, kFrameFlagResponse, encoded.value(),
                                    monotonicMillis() + options_.sessionIdleTimeoutMillis);
  };

  const auto found = state.transfers.find(message.deployment);
  if (found == state.transfers.end()) {
    ack.code = ErrorCode::NotFound;
    ack.detail = "no transfer is open for this deployment";
    return respond();
  }
  const TransferRecord current = found->second;
  if (!current.verified) {
    ack.code = ErrorCode::NotPrepared;
    ack.detail = "the staged artifact has not been verified";
    return respond();
  }
  if (!(message.digest == current.digest) || !(message.generation == current.generation)) {
    ack.code = ErrorCode::Conflict;
    ack.detail = "the stage message describes different content";
    return respond();
  }
  if (state.committedGeneration.isSet() && message.generation < state.committedGeneration) {
    ack.code = ErrorCode::StaleGeneration;
    ack.detail = "staging a generation older than the committed one is refused";
    return respond();
  }

  const std::string directory = liveKeyDirectory(current.key);
  std::error_code ec;
  std::filesystem::create_directories(directory + "/payload", ec);
  if (ec) {
    ack.code = ErrorCode::OpenFailed;
    ack.detail = "cannot create the live payload directory";
    return respond();
  }
  const std::string payloadPath = directory + "/payload/" +
                                  std::to_string(current.generation.value()) + "-" +
                                  current.digest.hex().substr(0, 12) + ".cfg";
  const Status copied = copyFileAtomic(stagingPath(message.deployment), payloadPath);
  if (!copied) {
    ack.code = copied.code();
    ack.detail = "cannot place the artifact into the live area";
    return respond();
  }

  TransferRecord staged = current;
  staged.staged = true;
  staged.updatedAtMillis = nowUnixMillis();
  CF_TRY(checkpointTransfer(staged));
  ack.staged = true;
  ack.code = ErrorCode::Ok;
  CF_TRY(respond());
  if (options_.faults.armed(fault::kAfterStage)) {
    Logger::global().warn(kComponent, "fault injection: dying after staging");
    crashNow(74);
  }
  return Status::ok();
}

Status TargetAgent::onApplyPrepare(Session& session, std::span<const std::uint8_t> payload) {
  CF_TRY_ASSIGN(const ApplyPrepareMessage message, decodeApplyPrepare(payload));
  AgentState& state = store_->state();

  ApplyPrepareAckMessage ack;
  ack.deployment = message.deployment;
  const auto respond = [&]() -> Status {
    auto encoded = encodeApplyPrepareAck(ack);
    if (!encoded) {
      return Status::fail(encoded.error());
    }
    return session.connection->send(FrameType::ApplyPrepareAck, kFrameFlagResponse, encoded.value(),
                                    monotonicMillis() + options_.sessionIdleTimeoutMillis);
  };

  if (state.guarantee == ApplyGuarantee::AtomicActivate) {
    ack.code = ErrorCode::UnexpectedMessage;
    ack.detail =
        "this target activates atomically; a prepare/commit window would weaken its contract";
    return respond();
  }
  const auto found = state.transfers.find(message.deployment);
  if (found == state.transfers.end() || !found->second.staged) {
    ack.code = ErrorCode::NotPrepared;
    ack.detail = "no staged artifact is available for this deployment";
    return respond();
  }
  const TransferRecord current = found->second;
  if (state.committedGeneration.isSet() && message.generation < state.committedGeneration) {
    ack.code = ErrorCode::StaleGeneration;
    ack.detail = "prepare refused: the generation is older than the committed one";
    return respond();
  }
  if (!(message.digest == current.digest) || !(message.generation == current.generation)) {
    ack.code = ErrorCode::Conflict;
    ack.detail = "prepare describes different content";
    return respond();
  }
  if (state.applyPrepared) {
    ack.code = ErrorCode::Busy;
    ack.detail = "a prepare window is already open";
    return respond();
  }

  const std::string directory = liveKeyDirectory(current.key);
  const std::string pendingPath = directory + "/pending";
  const std::string text = pointerText(current.generation, current.digest,
                                       state.committedArtifact.isSet() ? ArtifactId{} : ArtifactId{});
  // The pending marker records exactly what would be activated, so a restart can
  // prove whether the switch happened.
  const std::string marker = pointerText(current.generation, current.digest, ArtifactId{});
  (void)text;
  const Status written = writeFileAtomic(
      pendingPath, std::span<const std::uint8_t>(
                       reinterpret_cast<const std::uint8_t*>(marker.data()), marker.size()));
  if (!written) {
    ack.code = written.code();
    ack.detail = "cannot write the prepare marker";
    return respond();
  }
  ByteWriter prepareRecord(160);
  prepareRecord.string(current.deployment.str(), kMaxIdentifierLength);
  prepareRecord.u64(current.generation.value());
  prepareRecord.digest(current.digest);
  CF_TRY(store_->commit(JournalRecordType::AgentApplyPrepared, prepareRecord.span()));

  ack.prepared = true;
  ack.code = ErrorCode::Ok;
  CF_TRY(respond());
  if (options_.faults.armed(fault::kAfterPrepare)) {
    Logger::global().warn(kComponent, "fault injection: dying inside the prepare window");
    crashNow(75);
  }
  if (options_.faults.armed(fault::kDropAfterPrepare)) {
    Logger::global().warn(kComponent, "fault injection: closing the session inside the prepare window");
    session.connection->close();
    return Status::fail(ErrorCode::ConnectionClosed, "session dropped inside the prepare window");
  }
  return Status::ok();
}

Status TargetAgent::onApplyCommit(Session& session, std::span<const std::uint8_t> payload) {
  CF_TRY_ASSIGN(const ApplyCommitMessage message, decodeApplyCommit(payload));
  AgentState& state = store_->state();

  ApplyCommitAckMessage ack;
  ack.deployment = message.deployment;
  ack.state = state.committedGeneration.isSet() ? DeliveryState::Applied : DeliveryState::Prepared;
  ack.committedGeneration = state.committedGeneration;
  ack.committedDigest = state.committedDigest;
  const auto respond = [&]() -> Status {
    auto encoded = encodeApplyCommitAck(ack);
    if (!encoded) {
      return Status::fail(encoded.error());
    }
    return session.connection->send(FrameType::ApplyCommitAck, kFrameFlagResponse, encoded.value(),
                                    monotonicMillis() + options_.sessionIdleTimeoutMillis);
  };

  // Stale fencing comes first: a lower generation is refused before anything is
  // touched, whatever else the message claims.
  if (state.committedGeneration.isSet() && message.generation < state.committedGeneration) {
    state.staleOffersRefused += 1;
    CF_TRY(store_->commit(JournalRecordType::AgentRollbackNote, rollbackPayload(state)));
    ack.committed = false;
    ack.code = ErrorCode::StaleGeneration;
    ack.detail = "commit refused: the generation is older than the committed one";
    CF_TRY(respond());
    return sendNack(session, message.deployment, ConfigKey{}, message.generation, message.digest,
                    ErrorCode::StaleGeneration, "stale commit refused at the target");
  }
  if (state.committedGeneration.isSet() && message.generation == state.committedGeneration &&
      message.digest == state.committedDigest) {
    // Idempotent: the exact generation and content are already active. Nothing
    // is re-applied.
    state.duplicatesSuppressed += 1;
    CF_TRY(store_->commit(JournalRecordType::AgentRollbackNote, rollbackPayload(state)));
    ack.committed = true;
    ack.state = DeliveryState::Applied;
    ack.code = ErrorCode::DuplicateSuppressed;
    ack.detail = "the generation is already active; the commit was not re-applied";
    CF_TRY(respond());
    return sendAck(session, message.deployment, ConfigKey{}, message.generation, message.digest,
                   DeliveryState::Applied, state.committedDigest.isSet() ? 0u : 0u, false);
  }
  if (state.committedGeneration.isSet() && message.generation == state.committedGeneration &&
      !(message.digest == state.committedDigest)) {
    ack.committed = false;
    ack.code = ErrorCode::GenerationConflict;
    ack.detail = "a different digest is already committed for this generation";
    CF_TRY(respond());
    return sendNack(session, message.deployment, ConfigKey{}, message.generation, message.digest,
                    ErrorCode::GenerationConflict, "generation conflict at the target");
  }

  const auto found = state.transfers.find(message.deployment);
  if (found == state.transfers.end() || !found->second.staged) {
    // Not staged under this deployment. Accept a durable finding for the exact
    // content as proof that activation already happened, otherwise refuse.
    const AppliedFinding* finding = state.findFinding(ConfigKey{}, message.digest);
    bool recorded = false;
    for (const AppliedFinding& candidate : state.findings) {
      if (candidate.generation == message.generation && candidate.digest == message.digest &&
          isActivationState(candidate.state)) {
        recorded = true;
        break;
      }
    }
    (void)finding;
    if (!recorded) {
      ack.committed = false;
      ack.code = ErrorCode::NotPrepared;
      ack.detail = "no staged artifact is available for this deployment";
      CF_TRY(respond());
      return sendNack(session, message.deployment, ConfigKey{}, message.generation, message.digest,
                      ErrorCode::NotPrepared, "commit without a staged artifact");
    }
    ack.committed = true;
    ack.state = DeliveryState::Applied;
    ack.code = ErrorCode::DuplicateSuppressed;
    ack.detail = "activation for this content is already recorded";
    CF_TRY(respond());
    return sendAck(session, message.deployment, ConfigKey{}, message.generation, message.digest,
                   DeliveryState::Applied, 0, false);
  }

  const TransferRecord current = found->second;
  if (!(message.digest == current.digest) || !(message.generation == current.generation)) {
    ack.committed = false;
    ack.code = ErrorCode::Conflict;
    ack.detail = "commit describes different content than the staged artifact";
    CF_TRY(respond());
    return sendNack(session, message.deployment, current.key, message.generation, message.digest,
                    ErrorCode::Conflict, "commit content conflict");
  }

  const Status activated = activate(current, state.guarantee == ApplyGuarantee::PrepareCommitAbort);
  if (!activated) {
    ack.committed = false;
    ack.code = activated.code();
    ack.detail = activated.str();
    CF_TRY(respond());
    return sendNack(session, message.deployment, current.key, message.generation, message.digest,
                    activated.code(), activated.str());
  }

  ack.committed = true;
  ack.state = DeliveryState::Applied;
  ack.code = ErrorCode::Ok;
  ack.committedGeneration = state.committedGeneration;
  ack.committedDigest = state.committedDigest;
  CF_TRY(respond());
  if (options_.faults.armed(fault::kAfterCommit)) {
    Logger::global().warn(kComponent, "fault injection: dying after commit, before acknowledgement");
    crashNow(76);
  }
  return sendAck(session, message.deployment, current.key, current.generation, current.digest,
                 DeliveryState::Applied, current.totalBytes, false);
}

Status TargetAgent::activate(const DeploymentId&, const TransferRecord& transfer,
                             bool explicitPrepare) {
  return activate(transfer, explicitPrepare);
}

Status TargetAgent::activate(const TransferRecord& transfer, bool explicitPrepare) {
  AgentState& state = store_->state();
  const std::string directory = liveKeyDirectory(transfer.key);
  const std::string currentPath = directory + "/current";
  const std::string pendingPath = directory + "/pending";
  // The live pointer names the artifact it activated, so a restart can
  // reconstruct the committed identity without guessing.
  const std::string marker = pointerText(transfer.generation, transfer.digest, transfer.artifact);

  if (explicitPrepare) {
    if (!state.applyPrepared) {
      const Status prepared = writeFileAtomic(
          pendingPath, std::span<const std::uint8_t>(
                           reinterpret_cast<const std::uint8_t*>(marker.data()), marker.size()));
      if (!prepared) {
        return prepared;
      }
      ByteWriter record(160);
      record.string(transfer.deployment.str(), kMaxIdentifierLength);
      record.u64(transfer.generation.value());
      record.digest(transfer.digest);
      CF_TRY(store_->commit(JournalRecordType::AgentApplyPrepared, record.span()));
    }
  }

  if (options_.faults.armed(fault::kBeforeCommit)) {
    Logger::global().warn(kComponent, "fault injection: dying before the activation switch");
    crashNow(77);
  }

  // The activation switch: exactly one atomic replacement of the live pointer.
  const Status switched = writeFileAtomic(
      currentPath, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(marker.data()),
                                                 marker.size()));
  if (!switched) {
    return switched;
  }

  if (explicitPrepare) {
    std::error_code removed;
    std::filesystem::remove(pendingPath, removed);
  }

  CF_TRY(commitGeneration(transfer.deployment, transfer.key, transfer.generation, transfer.digest,
                          transfer.artifact));
  CF_TRY(prunePayloads(transfer.key));
  return Status::ok();
}

Status TargetAgent::commitGeneration(const DeploymentId& deployment, const ConfigKey& key,
                                     Generation generation, const Digest& digest,
                                     const ArtifactId& artifact) {
  AgentState& state = store_->state();
  if (state.applyPrepared) {
    ByteWriter resolved(32);
    resolved.u64(state.activations + 1u);
    CF_TRY(store_->commit(JournalRecordType::AgentApplyResolved, resolved.span()));
  }
  ByteWriter commitRecord(192);
  commitRecord.u64(generation.value());
  commitRecord.digest(digest);
  commitRecord.string(artifact.str(), kMaxIdentifierLength);
  CF_TRY(store_->commit(JournalRecordType::AgentTargetCommit, commitRecord.span()));

  ByteWriter finding(320);
  finding.string(key.str(), kMaxIdentifierLength);
  finding.u64(generation.value());
  finding.digest(digest);
  finding.string(artifact.str(), kMaxIdentifierLength);
  finding.string(deployment.str(), kMaxIdentifierLength);
  finding.u8(static_cast<std::uint8_t>(DeliveryState::Applied));
  finding.i64(nowUnixMillis());
  CF_TRY(store_->commit(JournalRecordType::AgentFindingUpsert, finding.span()));

  if (state.activations != 0xFFFFFFFFFFFFFFFFull) {
    state.activations += 1;
  }
  CF_TRY(store_->commit(JournalRecordType::AgentRollbackNote, rollbackPayload(state)));
  Logger::global().info(kComponent, "activated " + key.str() + " generation " +
                                        std::to_string(generation.value()) + " digest=" +
                                        shortDigest(digest));
  return Status::ok();
}

Status TargetAgent::onApplyAbort(Session& session, std::span<const std::uint8_t> payload) {
  CF_TRY_ASSIGN(const ApplyAbortMessage message, decodeApplyAbort(payload));
  AgentState& state = store_->state();
  ApplyAbortAckMessage ack;
  ack.deployment = message.deployment;
  const auto respond = [&]() -> Status {
    auto encoded = encodeApplyAbortAck(ack);
    if (!encoded) {
      return Status::fail(encoded.error());
    }
    return session.connection->send(FrameType::ApplyAbortAck, kFrameFlagResponse, encoded.value(),
                                    monotonicMillis() + options_.sessionIdleTimeoutMillis);
  };
  if (!state.applyPrepared) {
    ack.aborted = false;
    ack.code = ErrorCode::NotPrepared;
    ack.detail = "no prepare window is open";
    return respond();
  }
  if (!(message.deployment == state.preparedDeployment) ||
      !(message.generation == state.preparedGeneration)) {
    ack.aborted = false;
    ack.code = ErrorCode::Conflict;
    ack.detail = "the abort describes a different prepare window";
    return respond();
  }
  for (const auto& entry : state.transfers) {
    const TransferRecord& record = entry.second;
    if (record.deployment == state.preparedDeployment) {
      std::error_code removed;
      std::filesystem::remove(liveKeyDirectory(record.key) + "/pending", removed);
      break;
    }
  }
  state.applyRollbacks += 1;
  CF_TRY(store_->commit(JournalRecordType::AgentRollbackNote, rollbackPayload(state)));
  ByteWriter resolved(32);
  resolved.u64(state.activations);
  CF_TRY(store_->commit(JournalRecordType::AgentApplyResolved, resolved.span()));
  ack.aborted = true;
  ack.code = ErrorCode::Ok;
  return respond();
}

Status TargetAgent::onReconcileRequest(Session& session, std::span<const std::uint8_t> payload) {
  CF_TRY_ASSIGN(const ReconcileRequestMessage request, decodeReconcileRequest(payload));
  AgentState& state = store_->state();

  ReconcileReportMessage report;
  report.target = state.target;
  report.targetClass = state.klass;
  report.guarantee = state.guarantee;
  report.term = state.term;
  report.incarnation = state.incarnation;
  report.committedGeneration = state.committedGeneration;
  report.committedDigest = state.committedDigest;
  report.committedArtifact = state.committedArtifact;
  report.applyPrepared = state.applyPrepared;
  report.preparedDeployment = state.preparedDeployment;
  report.preparedGeneration = state.preparedGeneration;
  report.preparedDigest = state.preparedDigest;
  report.restartCount = state.restartCount;
  report.applyRollbacks = static_cast<std::uint32_t>(
      std::min<std::uint64_t>(state.applyRollbacks, 0xFFFFFFFFull));

  // A transfer is only resumable up to the bytes that are actually on disk.
  std::size_t index = 0;
  for (const auto& entry : state.transfers) {
    if (index >= kMaxTransfersInReport) {
      break;
    }
    const TransferRecord& record = entry.second;
    TransferStatusRecord status;
    status.deployment = record.deployment;
    status.stream = record.stream;
    status.key = record.key;
    status.generation = record.generation;
    status.digest = record.digest;
    status.totalBytes = record.totalBytes;
    std::error_code sizeError;
    const std::uintmax_t onDisk =
        std::filesystem::file_size(stagingPath(record.deployment), sizeError);
    const std::uint64_t usable =
        sizeError ? 0 : static_cast<std::uint64_t>(onDisk);
    status.bytesReceived = std::min(record.bytesReceived, usable);
    status.verified = record.verified && status.bytesReceived == record.totalBytes;
    status.staged = record.staged;
    report.transfers.push_back(std::move(status));
    index += 1;
  }
  const std::size_t requested = std::min<std::size_t>(request.maxFindings, kMaxFindingsInReport);
  const std::size_t available = state.findings.size();
  const std::size_t take = std::min(requested, available);
  for (std::size_t i = available - take; i < available; ++i) {
    const AppliedFinding& source = state.findings[i];
    ReconcileFinding finding;
    finding.key = source.key;
    finding.generation = source.generation;
    finding.digest = source.digest;
    finding.artifact = source.artifact;
    finding.deployment = source.deployment;
    finding.state = source.state;
    finding.recordedAtMillis = source.recordedAtMillis;
    report.findings.push_back(std::move(finding));
  }

  Logger::global().info(kComponent,
                        "reconcile report: committed=" +
                            std::to_string(report.committedGeneration.value()) + " transfers=" +
                            std::to_string(report.transfers.size()) + " findings=" +
                            std::to_string(report.findings.size()) + " prepared=" +
                            (report.applyPrepared ? "yes" : "no"));
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodeReconcileReport(report));
  return session.connection->send(FrameType::ReconcileReport, kFrameFlagResponse, encoded,
                                  monotonicMillis() + options_.sessionIdleTimeoutMillis);
}

Status TargetAgent::onRetire(Session& session, std::span<const std::uint8_t> payload) {
  CF_TRY_ASSIGN(const RetireMessage message, decodeRetire(payload));
  AgentState& state = store_->state();
  RetireAckMessage ack;
  ack.deployment = message.deployment;
  if (state.committedGeneration.isSet() && message.generation >= state.committedGeneration) {
    ack.retired = false;
    CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodeRetireAck(ack));
    return session.connection->send(FrameType::RetireAck, kFrameFlagResponse, encoded,
                                    monotonicMillis() + options_.sessionIdleTimeoutMillis);
  }
  CF_TRY(destroyTransfer(message.deployment, "retired by the distributor"));
  ack.retired = true;
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodeRetireAck(ack));
  return session.connection->send(FrameType::RetireAck, kFrameFlagResponse, encoded,
                                  monotonicMillis() + options_.sessionIdleTimeoutMillis);
}

Status TargetAgent::onPing(Session& session, std::span<const std::uint8_t> payload) {
  CF_TRY_ASSIGN(const PingMessage ping, decodePing(payload));
  PongMessage pong;
  pong.nonce = ping.nonce;
  CF_TRY_ASSIGN(const std::vector<std::uint8_t> encoded, encodePong(pong));
  return session.connection->send(FrameType::Pong, kFrameFlagResponse, encoded,
                                  monotonicMillis() + options_.sessionIdleTimeoutMillis);
}

}  // namespace cf
