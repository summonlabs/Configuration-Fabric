// Unit and property tests: typed identities, digests and derived identities.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <set>
#include <string>

#include "cf/ids.hpp"
#include "cf/rng.hpp"
#include "testing.hpp"

CF_TEST(unit, identifier_policy) {
  CF_EXPECT(cf::isValidIdentifier("router-1"));
  CF_EXPECT(cf::isValidIdentifier("fabric/underlay"));
  CF_EXPECT(cf::isValidIdentifier("a.b_c-d:e"));
  CF_EXPECT(!cf::isValidIdentifier(""));
  CF_EXPECT(!cf::isValidIdentifier("-leading"));
  CF_EXPECT(!cf::isValidIdentifier("has space"));
  CF_EXPECT(!cf::isValidIdentifier("has\ttab"));
  CF_EXPECT(!cf::isValidIdentifier("unicode-\xC3\xA9"));
  CF_EXPECT(!cf::isValidIdentifier(std::string(129, 'a')));
  CF_EXPECT(cf::isValidIdentifier(std::string(128, 'a')));
}

CF_TEST(unit, typed_parsers_reject_bad_input) {
  CF_EXPECT_OK(cf::parseTargetId("t-1"));
  CF_EXPECT_CODE(cf::parseTargetId(""), cf::ErrorCode::MissingField);
  CF_EXPECT_CODE(cf::parseConfigKey("bad key"), cf::ErrorCode::InvalidArgument);
  CF_EXPECT_CODE(cf::parseArtifactId("-x"), cf::ErrorCode::InvalidArgument);
  CF_EXPECT_OK(cf::parseNodeId("ctl-a"));
  CF_EXPECT_OK(cf::parseSchemaId("cf.underlay"));
  CF_EXPECT_CODE(cf::parseDeploymentId(""), cf::ErrorCode::MissingField);
}

CF_TEST(unit, strong_types_are_not_interchangeable) {
  // This test exists to document the type discipline: the following lines would
  // not compile, which is the point.
  //   cf::TargetId target = cf::parseConfigKey("x").value();
  //   cf::Generation generation = cf::Revision::fromValue(3);
  //   if (cf::Epoch::fromValue(1) < cf::Term::fromValue(2)) {}
  cf::TargetId target = cf::parseTargetId("t-1").value();
  cf::ConfigKey key = cf::parseConfigKey("k-1").value();
  CF_EXPECT(!(target == cf::TargetId{}));
  CF_EXPECT(!(key == cf::ConfigKey{}));
  CF_EXPECT_EQ(cf::Generation::fromValue(7).value(), std::uint64_t{7});
  CF_EXPECT(cf::Epoch::fromValue(1) < cf::Epoch::fromValue(2));
}

CF_TEST(unit, digest_parse_and_render) {
  const cf::Digest digest = cf::Digest::ofText("configuration");
  CF_EXPECT_EQ(digest.hex().size(), cf::kSha256HexChars);
  CF_EXPECT(digest.isSet());
  CF_EXPECT_OK(cf::Digest::parse(digest.hex()));
  CF_EXPECT_EQ(cf::Digest::parse(digest.hex()).value(), digest);
  CF_EXPECT_CODE(cf::Digest::parse("short"), cf::ErrorCode::MalformedInput);
  CF_EXPECT_CODE(cf::Digest::parse(std::string(64, 'z')), cf::ErrorCode::MalformedInput);
  CF_EXPECT(!cf::Digest{}.isSet());
  CF_EXPECT_EQ(cf::shortDigest(digest), digest.hex().substr(0, 12));
}

CF_TEST(unit, opaque_identity_round_trip) {
  const cf::IncarnationId incarnation = cf::IncarnationId(cf::secureRandom128());
  CF_EXPECT(incarnation.isSet());
  const auto parsed = cf::IncarnationId::parse(incarnation.hex());
  CF_EXPECT_OK(parsed);
  CF_EXPECT_EQ(parsed.value(), incarnation);
  CF_EXPECT_CODE(cf::IncarnationId::parse("nope"), cf::ErrorCode::MalformedInput);
  CF_EXPECT(!cf::IncarnationId{}.isSet());
}

CF_TEST(unit, guarantee_compatibility_is_total) {
  CF_EXPECT(cf::guaranteeSatisfies(cf::ApplyGuarantee::AtomicActivate,
                                   cf::GuaranteeRequirement::RequireAtomic));
  CF_EXPECT(!cf::guaranteeSatisfies(cf::ApplyGuarantee::PrepareCommitAbort,
                                    cf::GuaranteeRequirement::RequireAtomic));
  CF_EXPECT(cf::guaranteeSatisfies(cf::ApplyGuarantee::AtomicActivate,
                                   cf::GuaranteeRequirement::AllowPrepareCommit));
  CF_EXPECT(cf::guaranteeSatisfies(cf::ApplyGuarantee::PrepareCommitAbort,
                                   cf::GuaranteeRequirement::AllowPrepareCommit));
}

CF_TEST(unit, enum_names_round_trip) {
  for (std::uint8_t raw = 0; raw <= 2; ++raw) {
    const auto klass = static_cast<cf::TargetClass>(raw);
    cf::TargetClass parsed{};
    CF_EXPECT(cf::parseTargetClass(cf::targetClassName(klass), parsed));
    CF_EXPECT(parsed == klass);
  }
  for (std::uint8_t raw = 1; raw <= 2; ++raw) {
    const auto guarantee = static_cast<cf::ApplyGuarantee>(raw);
    cf::ApplyGuarantee parsedGuarantee{};
    CF_EXPECT(cf::parseApplyGuarantee(cf::applyGuaranteeName(guarantee), parsedGuarantee));
    CF_EXPECT(parsedGuarantee == guarantee);
    const auto requirement = static_cast<cf::GuaranteeRequirement>(raw);
    cf::GuaranteeRequirement parsedRequirement{};
    CF_EXPECT(
        cf::parseGuaranteeRequirement(cf::guaranteeRequirementName(requirement), parsedRequirement));
    CF_EXPECT(parsedRequirement == requirement);
  }
}

CF_TEST(property, derived_deployment_identity_is_deterministic) {
  const cf::TargetId target = cf::parseTargetId("rtr-1").value();
  const cf::ConfigKey key = cf::parseConfigKey("fabric/underlay").value();
  const cf::Digest digest = cf::Digest::ofText("payload");
  const cf::DeploymentId first =
      cf::deriveDeploymentId(target, key, cf::Generation::fromValue(3), digest);
  const cf::DeploymentId second =
      cf::deriveDeploymentId(target, key, cf::Generation::fromValue(3), digest);
  CF_EXPECT_EQ(first, second);
  CF_EXPECT(cf::isValidIdentifier(first.str()));

  // Any input change must change the identity.
  std::set<std::string> identities;
  identities.insert(first.str());
  identities.insert(
      cf::deriveDeploymentId(target, key, cf::Generation::fromValue(4), digest).str());
  identities.insert(cf::deriveDeploymentId(target, key, cf::Generation::fromValue(3),
                                           cf::Digest::ofText("other"))
                        .str());
  identities.insert(cf::deriveDeploymentId(cf::parseTargetId("rtr-2").value(), key,
                                           cf::Generation::fromValue(3), digest)
                        .str());
  identities.insert(cf::deriveDeploymentId(target, cf::parseConfigKey("other").value(),
                                           cf::Generation::fromValue(3), digest)
                        .str());
  CF_EXPECT_EQ(identities.size(), std::size_t{5});

  cf::Rng rng(cftest::runSeed());
  for (int i = 0; i < 64; ++i) {
    const std::uint64_t generation = rng.bounded(1000000) + 1;
    const auto stream = cf::deriveStreamId(first, cf::AttemptId::fromValue(generation));
    CF_EXPECT(stream.isSet());
    CF_EXPECT_EQ(stream.value(),
                 cf::deriveStreamId(first, cf::AttemptId::fromValue(generation)).value());
  }
}
