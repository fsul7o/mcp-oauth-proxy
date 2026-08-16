/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.athenz.mop.store.impl.memory;

import io.athenz.mop.model.UpstreamTokenRecord;
import io.athenz.mop.store.MemoryStoreQualifier;
import io.athenz.mop.store.UpstreamTokenStore;
import jakarta.enterprise.context.ApplicationScoped;
import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * In-memory {@link UpstreamTokenStore} for {@code server.token-store.implementation: memory}.
 * Reproduces the version-CAS rotate/revoke semantics of {@code UpstreamTokenStoreDynamoDbImpl}
 * against a {@link ConcurrentHashMap} keyed by {@code providerUserId}, so L2-promoted providers
 * (see {@code UpstreamProviderClassifier}, e.g. the "okta"-labeled default-tenant login used by
 * this pattern) work without ever touching {@code DynamoDbClient}/KMS/STS. Not persisted across
 * restarts.
 */
@ApplicationScoped
@MemoryStoreQualifier
public class UpstreamTokenStoreInMemoryImpl implements UpstreamTokenStore {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private final ConcurrentHashMap<String, UpstreamTokenRecord> byProviderUserId = new ConcurrentHashMap<>();

    @Override
    public void save(UpstreamTokenRecord record) {
        if (record == null || record.providerUserId() == null || record.providerUserId().isEmpty()) {
            throw new IllegalArgumentException("upstream save: providerUserId required");
        }
        long version = record.version() > 0 ? record.version() : 1L;
        UpstreamTokenRecord toStore = UpstreamTokenRecord.builder()
                .providerUserId(record.providerUserId())
                .encryptedOktaRefreshToken(record.encryptedOktaRefreshToken())
                .lastRotatedAt(record.lastRotatedAt())
                .version(version)
                .ttl(record.ttl())
                .createdAt(record.createdAt())
                .updatedAt(record.updatedAt())
                .status(record.status())
                .revokedAt(record.revokedAt())
                .revokedReason(record.revokedReason())
                .rotationCount(record.rotationCount())
                .lastMintedAccessToken(record.lastMintedAccessToken())
                .lastMintedAtExpiresAt(record.lastMintedAtExpiresAt())
                .lastMintedAtRotationVersion(record.lastMintedAtRotationVersion())
                .build();
        byProviderUserId.put(record.providerUserId(), toStore);
        log.info("event=upstream_token_created provider_user_id={} version={} status={} ttl={}",
                record.providerUserId(), version, record.status(), record.ttl());
    }

    @Override
    public Optional<UpstreamTokenRecord> get(String providerUserId) {
        if (providerUserId == null || providerUserId.isEmpty()) {
            return Optional.empty();
        }
        return Optional.ofNullable(byProviderUserId.get(providerUserId));
    }

    @Override
    public boolean updateWithVersionCheck(String providerUserId, String newPlainUpstreamRefreshToken, long expectedVersion) {
        return updateWithVersionCheckInternal(providerUserId, newPlainUpstreamRefreshToken,
                /* stagedAccessToken */ null, /* stagedAtExpiresAt */ 0L, expectedVersion);
    }

    @Override
    public boolean updateWithVersionCheckAndStagedAt(String providerUserId, String newPlainUpstreamRefreshToken,
                                                     String newAccessToken, long newAccessTokenExpiresAt,
                                                     long expectedVersion) {
        return updateWithVersionCheckInternal(providerUserId, newPlainUpstreamRefreshToken,
                newAccessToken, newAccessTokenExpiresAt, expectedVersion);
    }

    private boolean updateWithVersionCheckInternal(String providerUserId, String newPlainUpstreamRefreshToken,
                                                   String stagedAccessToken, long stagedAtExpiresAt,
                                                   long expectedVersion) {
        if (providerUserId == null || providerUserId.isEmpty() || newPlainUpstreamRefreshToken == null) {
            return false;
        }
        boolean[] updated = {false};
        byProviderUserId.computeIfPresent(providerUserId, (id, current) -> {
            if (current.version() != expectedVersion || !current.isActive()) {
                if (!current.isActive()) {
                    log.info("event=upstream_okta_rotate_skipped_revoked provider_user_id={} version={} status={}",
                            providerUserId, current.version(), current.status());
                }
                return current;
            }
            String now = Instant.now().toString();
            long newVersion = expectedVersion + 1;
            long newRotationCount = current.rotationCount() + 1L;
            String stagedAtValue = stagedAccessToken != null ? stagedAccessToken : "";
            long stagedExpiresAtValue = stagedAccessToken != null && stagedAtExpiresAt > 0L ? stagedAtExpiresAt : 0L;
            long stagedRotationVersionValue = stagedAccessToken != null ? newVersion : 0L;
            updated[0] = true;
            return UpstreamTokenRecord.builder()
                    .providerUserId(providerUserId)
                    .encryptedOktaRefreshToken(newPlainUpstreamRefreshToken)
                    .lastRotatedAt(now)
                    .version(newVersion)
                    .ttl(current.ttl())
                    .createdAt(current.createdAt() != null ? current.createdAt() : now)
                    .updatedAt(now)
                    .status(UpstreamTokenRecord.STATUS_ACTIVE)
                    .rotationCount(newRotationCount)
                    .lastMintedAccessToken(stagedAtValue)
                    .lastMintedAtExpiresAt(stagedExpiresAtValue)
                    .lastMintedAtRotationVersion(stagedRotationVersionValue)
                    .build();
        });
        if (updated[0]) {
            log.info("event=upstream_token_rotated provider_user_id={} prior_version={} staged_at={}",
                    providerUserId, expectedVersion, stagedAccessToken != null);
        } else {
            log.debug("upstream version check failed for provider_user_id={}", providerUserId);
        }
        return updated[0];
    }

    @Override
    public boolean markRevoked(String providerUserId, long expectedVersion, String reason) {
        if (providerUserId == null || providerUserId.isEmpty()) {
            return false;
        }
        boolean[] revoked = {false};
        byProviderUserId.computeIfPresent(providerUserId, (id, current) -> {
            if (current.version() != expectedVersion || !current.isActive()) {
                log.info("event=upstream_okta_revoke_noop provider_user_id={} expected_version={} actual_version={} status={}",
                        providerUserId, expectedVersion, current.version(), current.status());
                return current;
            }
            String now = Instant.now().toString();
            revoked[0] = true;
            return UpstreamTokenRecord.builder()
                    .providerUserId(providerUserId)
                    .encryptedOktaRefreshToken("")
                    .lastRotatedAt(current.lastRotatedAt() != null ? current.lastRotatedAt() : "")
                    .version(current.version())
                    .ttl(current.ttl())
                    .createdAt(current.createdAt() != null ? current.createdAt() : now)
                    .updatedAt(now)
                    .status(UpstreamTokenRecord.STATUS_REVOKED_INVALID_GRANT)
                    .revokedAt(now)
                    .revokedReason(reason != null ? reason : "")
                    .rotationCount(current.rotationCount())
                    .lastMintedAccessToken("")
                    .lastMintedAtExpiresAt(0L)
                    .lastMintedAtRotationVersion(0L)
                    .build();
        });
        if (revoked[0]) {
            log.warn("event=upstream_token_revoked provider_user_id={} expected_version={} reason=\"{}\"",
                    providerUserId, expectedVersion, reason);
        }
        return revoked[0];
    }

    @Override
    public void delete(String providerUserId) {
        if (providerUserId == null || providerUserId.isEmpty()) {
            return;
        }
        byProviderUserId.remove(providerUserId);
    }
}
