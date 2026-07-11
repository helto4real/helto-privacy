// Dependency-neutral browser validation for opaque private artifact leases.

const ARTIFACT_LEASE_URL = /^\/helto_privacy\/artifacts\/hp-lease-[A-Za-z0-9_-]{32}$/;

export class PrivacyArtifactLeaseError extends Error {
  constructor(code) {
    super("Private artifact lease is invalid.");
    this.name = "PrivacyArtifactLeaseError";
    this.code = String(code || "PRIVACY_ARTIFACT_LEASE_INVALID");
  }
}

export function normalizeArtifactLease(lease) {
  if (
    !lease
    || Object.keys(lease).sort().join(",") !== "expiresInSeconds,url"
    || !ARTIFACT_LEASE_URL.test(String(lease.url || ""))
    || !Number.isInteger(lease.expiresInSeconds)
    || lease.expiresInSeconds < 1
  ) {
    throw new PrivacyArtifactLeaseError("PRIVACY_ARTIFACT_LEASE_INVALID");
  }
  return Object.freeze({
    url: String(lease.url),
    expiresInSeconds: lease.expiresInSeconds,
  });
}

export function resolveArtifactLeaseURL(lease, apiURL = (path) => path) {
  if (typeof apiURL !== "function") {
    throw new PrivacyArtifactLeaseError("PRIVACY_ARTIFACT_URL_ADAPTER_INVALID");
  }
  return apiURL(normalizeArtifactLease(lease).url);
}
