// Unit, adversarial and concurrency tests: the immutable artifact store.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <atomic>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "cf/artifact.hpp"
#include "cf/codec.hpp"
#include "cf/rng.hpp"
#include "harness.hpp"
#include "testing.hpp"

namespace {

cf::ArtifactMetadata metadataFor(std::string_view body, const std::string& id = "cfg/a") {
  cf::ArtifactMetadata metadata;
  metadata.id = cf::parseArtifactId(id).value();
  metadata.revision = cf::Revision::fromValue(3);
  metadata.schema = cf::parseSchemaId("cf.test").value();
  metadata.schemaVersion = cf::SchemaVersion::fromValue(2);
  metadata.digest = cf::Digest::ofText(body);
  metadata.sizeBytes = body.size();
  metadata.mediaType = "text/plain";
  metadata.producer = "unit-test";
  metadata.producedAtMillis = 1;
  metadata.storedAtMillis = 2;
  return metadata;
}

std::unique_ptr<cf::ArtifactStore> openStore(const cf::test::TempDir& directory,
                                             cf::ArtifactStore::RecoveryReport& recovery,
                                             std::uint64_t maxBytes = 1024) {
  cf::ArtifactStore::Options options;
  options.root = directory.path() + "/artifacts";
  options.maxArtifactBytes = maxBytes;
  options.maxTotalBytes = 64u * 1024u;
  options.maxArtifacts = 16;
  auto store = cf::ArtifactStore::open(options, recovery);
  CF_EXPECT(store.hasValue());
  return store ? std::move(store).value() : nullptr;
}

}  // namespace

CF_TEST(unit, publish_verify_and_list) {
  cf::test::TempDir directory("artifact-unit");
  cf::ArtifactStore::RecoveryReport recovery;
  auto store = openStore(directory, recovery);
  CF_EXPECT(store != nullptr);
  const std::string body = "hostname rtr-1\n";
  const cf::ArtifactMetadata metadata = metadataFor(body);

  CF_EXPECT_OK(store->ingestBytes(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(body.data()), body.size()),
      metadata));
  CF_EXPECT(store->contains(metadata.digest));
  CF_EXPECT_EQ(store->artifactCount(), std::size_t{1});
  CF_EXPECT_EQ(store->usedBytes(), static_cast<std::uint64_t>(body.size()));
  CF_EXPECT_OK(store->verify(metadata.digest));

  const auto listed = store->list();
  CF_EXPECT_OK(listed);
  CF_EXPECT_EQ(listed.value().size(), std::size_t{1});
  CF_EXPECT_EQ(listed.value()[0].digest, metadata.digest);
  CF_EXPECT_EQ(listed.value()[0].schemaVersion.value(), std::uint32_t{2});

  // Re-publishing identical content is an idempotent success.
  CF_EXPECT_OK(store->ingestBytes(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(body.data()), body.size()),
      metadata));
  CF_EXPECT_EQ(store->artifactCount(), std::size_t{1});
}

CF_TEST(unit, declared_digest_must_match_content) {
  cf::test::TempDir directory("artifact-digest");
  cf::ArtifactStore::RecoveryReport recovery;
  auto store = openStore(directory, recovery);
  const std::string body = "real content";
  cf::ArtifactMetadata metadata = metadataFor(body);
  metadata.digest = cf::Digest::ofText("different content");
  const auto bytes =
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(body.data()), body.size());
  CF_EXPECT_CODE(store->ingestBytes(bytes, metadata), cf::ErrorCode::DigestMismatch);
  CF_EXPECT_EQ(store->artifactCount(), std::size_t{0});
  CF_EXPECT(!store->contains(metadata.digest));
}

CF_TEST(unit, declared_size_must_match_content) {
  cf::test::TempDir directory("artifact-size");
  cf::ArtifactStore::RecoveryReport recovery;
  auto store = openStore(directory, recovery);
  const std::string body = "0123456789";
  cf::ArtifactMetadata metadata = metadataFor(body);
  metadata.sizeBytes = 4;
  const auto bytes =
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(body.data()), body.size());
  CF_EXPECT_CODE(store->ingestBytes(bytes, metadata), cf::ErrorCode::SizeMismatch);
}

CF_TEST(adversarial, corrupted_payload_is_detected_and_quarantined) {
  cf::test::TempDir directory("artifact-corrupt");
  cf::ArtifactStore::RecoveryReport recovery;
  auto store = openStore(directory, recovery);
  const std::string body = "configuration payload for corruption testing";
  const cf::ArtifactMetadata metadata = metadataFor(body);
  CF_EXPECT_OK(store->ingestBytes(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(body.data()), body.size()),
      metadata));

  // Flip one byte in the stored payload, exactly as a bad sector would.
  const std::string path = store->payloadPath(metadata.digest);
  std::FILE* file = std::fopen(path.c_str(), "r+b");
  CF_EXPECT(file != nullptr);
  if (file != nullptr) {
    CF_EXPECT(std::fseek(file, 3, SEEK_SET) == 0);
    const std::uint8_t hostile = 0xFF;
    CF_EXPECT(std::fwrite(&hostile, 1, 1, file) == 1);
    std::fclose(file);
  }

  CF_EXPECT_CODE(store->verify(metadata.digest), cf::ErrorCode::DigestMismatch);
  // The artifact is gone from the index, not silently returned.
  CF_EXPECT(!store->contains(metadata.digest));
  CF_EXPECT(std::filesystem::exists(path + ".corrupt"));
}

CF_TEST(adversarial, oversize_and_budget_are_refused) {
  cf::test::TempDir directory("artifact-budget");
  cf::ArtifactStore::RecoveryReport recovery;
  cf::ArtifactStore::Options options;
  options.root = directory.path() + "/artifacts";
  options.maxArtifactBytes = 32;
  options.maxTotalBytes = 64;
  options.maxArtifacts = 2;
  auto opened = cf::ArtifactStore::open(options, recovery);
  CF_EXPECT_OK(opened);
  if (!opened) {
    return;
  }
  cf::ArtifactStore& store = *opened.value();

  const std::string tooBig(64, 'x');
  const cf::ArtifactMetadata bigMetadata = metadataFor(tooBig);
  CF_EXPECT_CODE(store.ingestBytes(std::span<const std::uint8_t>(
                                       reinterpret_cast<const std::uint8_t*>(tooBig.data()),
                                       tooBig.size()),
                                   bigMetadata),
                 cf::ErrorCode::OversizePayload);

  const std::string first(20, 'a');
  const std::string second(20, 'b');
  const std::string third(20, 'c');
  CF_EXPECT_OK(store.ingestBytes(std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t*>(first.data()),
                                     first.size()),
                                 metadataFor(first)));
  CF_EXPECT_OK(store.ingestBytes(std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t*>(second.data()),
                                     second.size()),
                                 metadataFor(second)));
  CF_EXPECT_CODE(store.ingestBytes(std::span<const std::uint8_t>(
                                       reinterpret_cast<const std::uint8_t*>(third.data()),
                                       third.size()),
                                   metadataFor(third)),
                 cf::ErrorCode::StoreFull);
  CF_EXPECT_EQ(store.artifactCount(), std::size_t{2});
}

CF_TEST(unit, partial_publish_is_removed_on_reopen) {
  cf::test::TempDir directory("artifact-partial");
  const std::string root = directory.path() + "/artifacts";
  std::filesystem::create_directories(root + "/payload");
  cf::test::writeTextFile(root + "/payload/.staging-deadbeef.part", "half written");

  cf::ArtifactStore::RecoveryReport recovery;
  cf::ArtifactStore::Options options;
  options.root = root;
  auto store = cf::ArtifactStore::open(options, recovery);
  CF_EXPECT_OK(store);
  CF_EXPECT_EQ(recovery.removedPartialFiles, std::size_t{1});
  CF_EXPECT(!std::filesystem::exists(root + "/payload/.staging-deadbeef.part"));
}

CF_TEST(unit, identity_is_content_addressed_across_restart) {
  cf::test::TempDir directory("artifact-restart");
  const std::string body = "stable content";
  const cf::ArtifactMetadata metadata = metadataFor(body);
  {
    cf::ArtifactStore::RecoveryReport recovery;
    auto store = openStore(directory, recovery);
    CF_EXPECT_OK(store->ingestBytes(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(body.data()),
                                      body.size()),
        metadata));
  }
  {
    cf::ArtifactStore::RecoveryReport recovery;
    auto store = openStore(directory, recovery);
    CF_EXPECT_EQ(recovery.artifactsIndexed, std::size_t{1});
    CF_EXPECT(store->contains(metadata.digest));
    const auto loaded = store->metadata(metadata.digest);
    CF_EXPECT_OK(loaded);
    CF_EXPECT_EQ(loaded.value().id.str(), metadata.id.str());
    CF_EXPECT_EQ(loaded.value().digest, metadata.digest);
    CF_EXPECT_OK(store->verify(metadata.digest));
  }
}

CF_TEST(unit, metadata_record_round_trip_and_integrity) {
  const cf::ArtifactMetadata metadata = metadataFor("payload");
  const auto encoded = cf::encodeArtifactMetadata(metadata);
  CF_EXPECT_OK(encoded);
  const auto decoded = cf::decodeArtifactMetadata(encoded.value());
  CF_EXPECT_OK(decoded);
  CF_EXPECT(decoded.value() == metadata);

  // Every single-byte corruption must be refused.
  for (std::size_t i = 0; i < encoded.value().size(); ++i) {
    std::vector<std::uint8_t> damaged = encoded.value();
    damaged[i] = static_cast<std::uint8_t>(damaged[i] ^ 0x01u);
    const auto result = cf::decodeArtifactMetadata(damaged);
    CF_EXPECT(!result.hasValue());
  }
  // Truncation is refused too.
  for (std::size_t length = 0; length < encoded.value().size(); ++length) {
    const auto result = cf::decodeArtifactMetadata(
        std::span<const std::uint8_t>(encoded.value().data(), length));
    CF_EXPECT(!result.hasValue());
  }
}

CF_TEST(concurrency, parallel_publish_and_verify) {
  cf::test::TempDir directory("artifact-concurrent");
  cf::ArtifactStore::RecoveryReport recovery;
  cf::ArtifactStore::Options options;
  options.root = directory.path() + "/artifacts";
  options.maxArtifacts = 256;
  options.maxTotalBytes = 1u << 20;
  auto store = cf::ArtifactStore::open(options, recovery);
  CF_EXPECT_OK(store);

  std::atomic<int> failures{0};
  std::vector<std::thread> threads;
  for (int worker = 0; worker < 8; ++worker) {
    threads.emplace_back([&store, &failures, worker] {
      for (int iteration = 0; iteration < 12; ++iteration) {
        const std::string body =
            "worker-" + std::to_string(worker) + "-iteration-" + std::to_string(iteration);
        const cf::ArtifactMetadata metadata = metadataFor(body);
        const cf::Status ingested = store.value()->ingestBytes(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(body.data()),
                                          body.size()),
            metadata);
        if (!ingested) {
          failures += 1;
          continue;
        }
        if (!store.value()->verify(metadata.digest)) {
          failures += 1;
        }
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  CF_EXPECT_EQ(failures.load(), 0);
  CF_EXPECT_EQ(store.value()->artifactCount(), std::size_t{8 * 12});
}

CF_TEST(unit, garbage_collection_removes_only_unreferenced) {
  cf::test::TempDir directory("artifact-gc");
  cf::ArtifactStore::RecoveryReport recovery;
  auto store = openStore(directory, recovery);
  const std::string keep = "keep me";
  const std::string drop = "drop me";
  CF_EXPECT_OK(store->ingestBytes(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(keep.data()), keep.size()),
      metadataFor(keep, "cfg/keep")));
  CF_EXPECT_OK(store->ingestBytes(
      std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(drop.data()), drop.size()),
      metadataFor(drop, "cfg/drop")));
  std::size_t removed = 0;
  CF_EXPECT_OK(store->collectGarbage({cf::Digest::ofText(keep)}, &removed));
  CF_EXPECT_EQ(removed, std::size_t{1});
  CF_EXPECT(store->contains(cf::Digest::ofText(keep)));
  CF_EXPECT(!store->contains(cf::Digest::ofText(drop)));
}
