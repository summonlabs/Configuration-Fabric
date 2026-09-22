// Configuration Fabric - vendor-neutral Fabric OS runtime.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cf/lifecycle.hpp"

#include <array>

#include "cf/contract.hpp"

namespace cf {
namespace {

/// Transition relation. Index by (from, to); true means legal.
/// Prepared..Acknowledged form the happy path in order. Failure may interrupt
/// any pre-acknowledgement step. Rejection is only legal from a state where
/// nothing has been activated yet. Retirement is legal from any state because a
/// deployment set can always be superseded.
///
/// Every pre-activation state may also move straight to Applied. That is not a
/// shortcut: a delivery identity is derived from (target, config key,
/// generation, digest), so a target reporting that exact generation and digest
/// as active is reporting the outcome of a previous attempt at this same
/// delivery. Refusing to record it would leave the fabric unable to describe a
/// target it can plainly see.
constexpr std::array<std::array<bool, 11>, 11> kTransitions = {{
    // to:      Prep   Offr   Xfer   Veri   Stag   Appl   Ackd   Fail   Rejc   Retd   (unused)
    /* Prep */ {{false, true,  false, false, false, true,  false, true,  true,  true,  false}},
    /* Offr */ {{false, false, true,  false, false, true,  false, true,  true,  true,  false}},
    /* Xfer */ {{false, false, false, true,  false, true,  false, true,  true,  true,  false}},
    /* Veri */ {{false, false, false, false, true,  true,  false, true,  true,  true,  false}},
    /* Stag */ {{false, false, false, false, false, true,  false, true,  true,  true,  false}},
    /* Appl */ {{false, false, false, false, false, false, true,  true,  false, true,  false}},
    /* Ackd */ {{false, false, false, false, false, false, false, false, false, true,  false}},
    /* Fail */ {{true,  false, false, false, false, true,  false, false, true,  true,  false}},
    /* Rejc */ {{false, false, false, false, false, false, false, false, false, true,  false}},
    /* Retd */ {{false, false, false, false, false, false, false, false, false, false, false}},
    /* ---- */ {{false, false, false, false, false, false, false, false, false, false, false}},
}};

[[nodiscard]] constexpr std::size_t indexOf(DeliveryState state) noexcept {
  return static_cast<std::size_t>(state) - 1u;
}

}  // namespace

std::string_view deliveryStateName(DeliveryState state) noexcept {
  switch (state) {
    case DeliveryState::Prepared:
      return "prepared";
    case DeliveryState::Offered:
      return "offered";
    case DeliveryState::Transferred:
      return "transferred";
    case DeliveryState::Verified:
      return "verified";
    case DeliveryState::Staged:
      return "staged";
    case DeliveryState::Applied:
      return "applied";
    case DeliveryState::Acknowledged:
      return "acknowledged";
    case DeliveryState::Failed:
      return "failed";
    case DeliveryState::Rejected:
      return "rejected";
    case DeliveryState::Retired:
      return "retired";
  }
  return "unknown";
}

bool parseDeliveryState(std::string_view text, DeliveryState& out) noexcept {
  const std::array<std::pair<std::string_view, DeliveryState>, 10> table = {{
      {"prepared", DeliveryState::Prepared},
      {"offered", DeliveryState::Offered},
      {"transferred", DeliveryState::Transferred},
      {"verified", DeliveryState::Verified},
      {"staged", DeliveryState::Staged},
      {"applied", DeliveryState::Applied},
      {"acknowledged", DeliveryState::Acknowledged},
      {"failed", DeliveryState::Failed},
      {"rejected", DeliveryState::Rejected},
      {"retired", DeliveryState::Retired},
  }};
  for (const auto& entry : table) {
    if (entry.first == text) {
      out = entry.second;
      return true;
    }
  }
  return false;
}

std::uint8_t deliveryStateRank(DeliveryState state) noexcept {
  switch (state) {
    case DeliveryState::Prepared:
      return 0;
    case DeliveryState::Offered:
      return 1;
    case DeliveryState::Transferred:
      return 2;
    case DeliveryState::Verified:
      return 3;
    case DeliveryState::Staged:
      return 4;
    case DeliveryState::Applied:
      return 5;
    case DeliveryState::Acknowledged:
      return 6;
    case DeliveryState::Failed:
      return 7;
    case DeliveryState::Rejected:
      return 8;
    case DeliveryState::Retired:
      return 9;
  }
  return 255;
}

bool isActivationState(DeliveryState state) noexcept {
  return state == DeliveryState::Applied || state == DeliveryState::Acknowledged;
}

bool isTerminalState(DeliveryState state) noexcept {
  return state == DeliveryState::Acknowledged || state == DeliveryState::Rejected ||
         state == DeliveryState::Retired;
}

bool isPendingState(DeliveryState state) noexcept {
  return state == DeliveryState::Prepared || state == DeliveryState::Offered ||
         state == DeliveryState::Transferred || state == DeliveryState::Verified ||
         state == DeliveryState::Staged || state == DeliveryState::Applied ||
         state == DeliveryState::Failed;
}

bool isLegalTransition(DeliveryState from, DeliveryState to) noexcept {
  const std::size_t fromIndex = indexOf(from);
  const std::size_t toIndex = indexOf(to);
  if (fromIndex >= kTransitions.size() || toIndex >= kTransitions[0].size()) {
    return false;
  }
  return kTransitions[fromIndex][toIndex];
}

std::string renderTransitionTable() {
  std::string out;
  out.append("configuration-fabric delivery lifecycle\n");
  out.append("states:");
  for (std::uint8_t raw = 1; raw <= 10; ++raw) {
    const auto state = static_cast<DeliveryState>(raw);
    out.push_back(' ');
    out.append(deliveryStateName(state));
  }
  out.push_back('\n');
  for (std::uint8_t raw = 1; raw <= 10; ++raw) {
    const auto from = static_cast<DeliveryState>(raw);
    out.append("  ");
    out.append(deliveryStateName(from));
    out.append(" ->");
    bool any = false;
    for (std::uint8_t target = 1; target <= 10; ++target) {
      const auto to = static_cast<DeliveryState>(target);
      if (isLegalTransition(from, to)) {
        out.push_back(' ');
        out.append(deliveryStateName(to));
        any = true;
      }
    }
    if (!any) {
      out.append(" (terminal)");
    }
    out.push_back('\n');
  }
  return out;
}

std::string_view evidenceKindName(EvidenceKind kind) noexcept {
  switch (kind) {
    case EvidenceKind::Created:
      return "created";
    case EvidenceKind::OfferedToTarget:
      return "offered-to-target";
    case EvidenceKind::BytesAccepted:
      return "bytes-accepted";
    case EvidenceKind::DigestVerified:
      return "digest-verified";
    case EvidenceKind::StagedAtTarget:
      return "staged-at-target";
    case EvidenceKind::ApplyPrepared:
      return "apply-prepared";
    case EvidenceKind::ActivationReported:
      return "activation-reported";
    case EvidenceKind::AcknowledgementRecorded:
      return "acknowledgement-recorded";
    case EvidenceKind::ReconcileObserved:
      return "reconcile-observed";
    case EvidenceKind::FailureReported:
      return "failure-reported";
    case EvidenceKind::Refused:
      return "refused";
    case EvidenceKind::Superseded:
      return "superseded";
    case EvidenceKind::Retried:
      return "retried";
  }
  return "unknown";
}

bool parseEvidenceKind(std::string_view text, EvidenceKind& out) noexcept {
  for (std::uint8_t raw = 1; raw <= 13; ++raw) {
    const auto kind = static_cast<EvidenceKind>(raw);
    if (evidenceKindName(kind) == text) {
      out = kind;
      return true;
    }
  }
  return false;
}

std::string LifecycleEvent::render() const {
  std::string out;
  out.reserve(192);
  out.append(evidenceKindName(kind));
  out.append(" ");
  out.append(deliveryStateName(from));
  out.append("->");
  out.append(deliveryStateName(to));
  out.append(" gen=");
  out.append(std::to_string(generation.value()));
  out.append(" digest=");
  out.append(shortDigest(digest));
  if (code != ErrorCode::Ok) {
    out.append(" code=");
    out.append(errorCodeName(code));
  }
  out.append(" epoch=");
  out.append(std::to_string(authorityEpoch.value()));
  if (authorityIncarnation.isSet()) {
    out.append(" inc=");
    out.append(authorityIncarnation.hex().substr(0, 8));
  }
  if (targetTerm.isSet()) {
    out.append(" term=");
    out.append(std::to_string(targetTerm.value()));
  }
  if (targetIncarnation.isSet()) {
    out.append(" target-inc=");
    out.append(targetIncarnation.hex().substr(0, 8));
  }
  if (fromReconciliation) {
    out.append(" evidence=reconciliation");
  }
  if (!detail.empty()) {
    out.append(" detail=");
    out.append(detail);
  }
  return out;
}

Result<DeliveryState> applyTransition(DeliveryState from, DeliveryState to,
                                      std::string_view what) {
  if (!isLegalTransition(from, to)) {
    std::string detail;
    detail.append("from=");
    detail.append(deliveryStateName(from));
    detail.append(" to=");
    detail.append(deliveryStateName(to));
    detail.append(" at=");
    detail.append(what);
    return Result<DeliveryState>::fail(ErrorCode::IllegalTransition,
                                       "delivery lifecycle transition is not permitted", detail);
  }
  return Result<DeliveryState>::ok(to);
}

}  // namespace cf
