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
package io.athenz.mop.service.impl.memory;

import io.athenz.mop.model.RefreshTokenLockKey;
import io.athenz.mop.model.RefreshTokenRecord;
import io.athenz.mop.model.RefreshTokenRotateResult;
import io.athenz.mop.model.RefreshTokenValidationResult;
import io.athenz.mop.service.RefreshTokenService;
import io.athenz.mop.store.MemoryStoreQualifier;
import io.athenz.mop.store.impl.aws.RefreshTableConstants;
import jakarta.enterprise.context.ApplicationScoped;
import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * In-memory {@link RefreshTokenService} for {@code server.token-store.implementation: memory}.
 * Reproduces the ACTIVE -&gt; ROTATED -&gt; new-ACTIVE-child state machine (and the rotated-grace
 * window from {@code RefreshTokenServiceImpl.resolveRotated}) against a {@link ConcurrentHashMap}
 * index instead of DynamoDB, so replay detection and grace-window behavior stay identical without
 * ever touching {@code DynamoDbClient}/KMS/STS. Not persisted across restarts.
 */
@ApplicationScoped
@MemoryStoreQualifier
public class RefreshTokenServiceInMemoryImpl implements RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final int TOKEN_BYTES = 32;
    private static final String TOKEN_PREFIX = "rt_";
    private static final String SHA_256 = "SHA-256";

    private final SecureRandom secureRandom = new SecureRandom();

    @ConfigProperty(name = "server.refresh-token.expiry-seconds", defaultValue = "7776000")
    long expirySeconds;

    @ConfigProperty(name = "server.refresh-token.ttl-buffer-days", defaultValue = "7")
    int ttlBufferDays;

    @ConfigProperty(name = "server.refresh-token.rotated-grace-seconds", defaultValue = "7200")
    long rotatedGraceSeconds;

    @ConfigProperty(name = "server.refresh-token.family-idle-grace-seconds", defaultValue = "0")
    long familyIdleGraceSeconds;

    /** Primary store: refresh_token_id -&gt; record. */
    private final ConcurrentHashMap<String, RefreshTokenRecord> byId = new ConcurrentHashMap<>();

    /** Secondary index: SHA-256(rawToken) -&gt; refresh_token_id. */
    private final ConcurrentHashMap<String, String> hashToId = new ConcurrentHashMap<>();

    /** Secondary index: token_family_id -&gt; refresh_token_ids in the family. */
    private final ConcurrentHashMap<String, Set<String>> familyToIds = new ConcurrentHashMap<>();

    /** Secondary index: provider_user_id (provider#userId) -&gt; refresh_token_ids. */
    private final ConcurrentHashMap<String, Set<String>> userProviderToIds = new ConcurrentHashMap<>();

    @Override
    public String generateSecureToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return TOKEN_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Override
    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256);
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    public String store(String userId, String clientId, String provider, String providerSubject,
                       String upstreamRefreshToken, String audience) {
        String refreshTokenId = UUID.randomUUID().toString();
        String rawToken = generateSecureToken();
        String tokenHash = hashToken(rawToken);
        String providerUserId = provider + "#" + userId;
        long now = System.currentTimeMillis() / 1000;
        long expiresAt = now + expirySeconds;
        long ttl = expiresAt + (ttlBufferDays * 86400L);

        RefreshTokenRecord record = new RefreshTokenRecord(
                refreshTokenId,
                providerUserId,
                userId,
                clientId,
                provider,
                (audience != null && !audience.isEmpty()) ? audience : null,
                providerSubject != null ? providerSubject : "",
                (upstreamRefreshToken != null && !upstreamRefreshToken.isEmpty()) ? upstreamRefreshToken : null,
                RefreshTableConstants.STATUS_ACTIVE,
                refreshTokenId,
                null,
                null,
                0L,
                now,
                expiresAt,
                ttl);

        byId.put(refreshTokenId, record);
        hashToId.put(tokenHash, refreshTokenId);
        indexAdd(familyToIds, refreshTokenId, refreshTokenId);
        indexAdd(userProviderToIds, providerUserId, refreshTokenId);

        log.info("store: saved refresh token (memory) refresh_token_id={} userId={} provider={} audience={} client_id={} expires_at={}",
                refreshTokenId, userId, provider, audience, clientId, expiresAt);
        return rawToken;
    }

    @Override
    public Optional<RefreshTokenLockKey> lookupUserIdAndProviderForLock(String refreshToken, String clientId) {
        if (refreshToken == null || refreshToken.isEmpty() || clientId == null || clientId.isEmpty()) {
            return Optional.empty();
        }
        RefreshTokenRecord record = lookupByHash(hashToken(refreshToken));
        if (record == null || !clientId.equals(record.clientId())) {
            return Optional.empty();
        }
        return Optional.of(new RefreshTokenLockKey(record.userId(), record.provider()));
    }

    @Override
    public RefreshTokenValidationResult validate(String refreshToken, String clientId) {
        if (refreshToken == null || refreshToken.isEmpty() || clientId == null || clientId.isEmpty()) {
            log.info("validate: invalid grant - missing refresh_token or client_id");
            return RefreshTokenValidationResult.invalid();
        }
        RefreshTokenRecord record = lookupByHash(hashToken(refreshToken));
        if (record == null) {
            log.info("validate: invalid grant - no record found for refresh token (client_id={})", clientId);
            return RefreshTokenValidationResult.invalid();
        }
        long now = System.currentTimeMillis() / 1000;
        if (now > record.expiresAt()) {
            log.info("validate: invalid grant - refresh token expired; userId={} provider={} expires_at={} now={}",
                    record.userId(), record.provider(), record.expiresAt(), now);
            return RefreshTokenValidationResult.invalid();
        }
        if (!clientId.equals(record.clientId())) {
            log.info("validate: invalid grant - client_id mismatch; stored={} request={}", record.clientId(), clientId);
            return RefreshTokenValidationResult.invalid();
        }
        switch (record.status()) {
            case RefreshTableConstants.STATUS_REVOKED:
                return RefreshTokenValidationResult.revoked(record);
            case RefreshTableConstants.STATUS_ROTATED:
                return resolveRotated(record, now);
            case RefreshTableConstants.STATUS_ACTIVE:
                return RefreshTokenValidationResult.active(record);
            default:
                log.info("validate: invalid grant - unknown status={}; userId={}", record.status(), record.userId());
                return RefreshTokenValidationResult.invalid();
        }
    }

    /** In-memory equivalent of {@code RefreshTokenServiceImpl.resolveRotated}. */
    private RefreshTokenValidationResult resolveRotated(RefreshTokenRecord record, long now) {
        long rotatedAt = record.rotatedAt();
        long ageSeconds = rotatedAt > 0 ? (now - rotatedAt) : Long.MAX_VALUE;
        if (rotatedAt <= 0 || ageSeconds > rotatedGraceSeconds) {
            return RefreshTokenValidationResult.rotatedReplay(record);
        }
        RefreshTokenRecord successor = queryLatestActiveInFamily(record.tokenFamilyId());
        if (successor == null) {
            log.warn("validate: ROTATED row within token-age grace but no live ACTIVE successor in familyId={}; falling back to replay",
                    record.tokenFamilyId());
            return RefreshTokenValidationResult.rotatedReplay(record);
        }
        if (familyIdleGraceSeconds > 0) {
            long familyIdleSeconds = successor.issuedAt() > 0 ? (now - successor.issuedAt()) : Long.MAX_VALUE;
            if (familyIdleSeconds > familyIdleGraceSeconds) {
                log.info("validate: ROTATED row in token-age grace but family-idle exceeded familyId={} ageSec={} familyIdleSec={}; falling back to replay",
                        record.tokenFamilyId(), ageSeconds, familyIdleSeconds);
                return RefreshTokenValidationResult.rotatedReplay(record);
            }
        }
        log.info("validate: ROTATED row within grace window; serving from successor familyId={} ageSec={}",
                record.tokenFamilyId(), ageSeconds);
        return RefreshTokenValidationResult.rotatedGraceSuccessor(record, successor);
    }

    @Override
    public RefreshTokenRotateResult rotate(String refreshToken, String clientId) {
        if (refreshToken == null || refreshToken.isEmpty() || clientId == null || clientId.isEmpty()) {
            return null;
        }
        RefreshTokenValidationResult result = validate(refreshToken, clientId);
        if (result.status() != RefreshTokenValidationResult.Status.ACTIVE || result.record() == null) {
            return null;
        }
        long now = System.currentTimeMillis() / 1000;
        return rotateRecord(result.record(), now);
    }

    @Override
    public RefreshTokenRotateResult rotateGraceSuccessor(RefreshTokenRecord successor) {
        if (successor == null || successor.refreshTokenId() == null || successor.providerUserId() == null) {
            return null;
        }
        RefreshTokenRecord current = byId.get(successor.refreshTokenId());
        if (current == null || !current.providerUserId().equals(successor.providerUserId())) {
            log.warn("rotateGraceSuccessor: successor row not found by primary key");
            return null;
        }
        if (!RefreshTableConstants.STATUS_ACTIVE.equals(current.status())) {
            log.info("rotateGraceSuccessor: successor no longer ACTIVE (status={}); aborting", current.status());
            return null;
        }
        long now = System.currentTimeMillis() / 1000;
        if (current.expiresAt() > 0 && now > current.expiresAt()) {
            log.info("rotateGraceSuccessor: successor expired; aborting");
            return null;
        }
        return rotateRecord(current, now);
    }

    /**
     * Atomically transitions {@code current} ACTIVE -&gt; ROTATED and inserts a new ACTIVE child,
     * mirroring the DynamoDB {@code TransactWriteItems} with condition {@code status = ACTIVE} in
     * {@code RefreshTokenServiceImpl.rotateRecord}. The {@link ConcurrentHashMap#computeIfPresent}
     * CAS on {@code current.refreshTokenId()} is the in-memory equivalent of the conditional write:
     * only one concurrent caller can win the ACTIVE -&gt; ROTATED transition for a given row, so two
     * threads racing to rotate the same token can never both mint a successor.
     */
    private RefreshTokenRotateResult rotateRecord(RefreshTokenRecord current, long now) {
        String newTokenId = UUID.randomUUID().toString();
        String newRawToken = generateSecureToken();
        String newHash = hashToken(newRawToken);
        String providerUserId = current.provider() + "#" + current.userId();

        boolean[] transitioned = {false};
        byId.computeIfPresent(current.refreshTokenId(), (id, existing) -> {
            if (!RefreshTableConstants.STATUS_ACTIVE.equals(existing.status())) {
                return existing;
            }
            transitioned[0] = true;
            return new RefreshTokenRecord(
                    existing.refreshTokenId(), existing.providerUserId(), existing.userId(), existing.clientId(),
                    existing.provider(), existing.audience(), existing.providerSubject(), existing.encryptedUpstreamRefreshToken(),
                    RefreshTableConstants.STATUS_ROTATED, existing.tokenFamilyId(), existing.rotatedFrom(), newTokenId,
                    now, existing.issuedAt(), existing.expiresAt(), existing.ttl());
        });
        if (!transitioned[0]) {
            log.info("rotateRecord: row already rotated/revoked; falling back to grace path");
            return null;
        }

        RefreshTokenRecord newRecord = new RefreshTokenRecord(
                newTokenId,
                providerUserId,
                current.userId(),
                current.clientId(),
                current.provider(),
                current.audience(),
                current.providerSubject(),
                current.encryptedUpstreamRefreshToken(),
                RefreshTableConstants.STATUS_ACTIVE,
                current.tokenFamilyId(),
                current.refreshTokenId(),
                null,
                0L,
                now,
                current.expiresAt(),
                current.ttl());

        byId.put(newTokenId, newRecord);
        hashToId.put(newHash, newTokenId);
        indexAdd(familyToIds, current.tokenFamilyId(), newTokenId);
        indexAdd(userProviderToIds, providerUserId, newTokenId);

        return new RefreshTokenRotateResult(newRawToken, newTokenId, providerUserId);
    }

    @Override
    public void revokeFamily(String tokenFamilyId) {
        if (tokenFamilyId == null || tokenFamilyId.isEmpty()) {
            return;
        }
        Set<String> ids = familyToIds.get(tokenFamilyId);
        if (ids == null || ids.isEmpty()) {
            return;
        }
        for (String id : ids) {
            byId.computeIfPresent(id, (k, existing) -> new RefreshTokenRecord(
                    existing.refreshTokenId(), existing.providerUserId(), existing.userId(), existing.clientId(),
                    existing.provider(), existing.audience(), existing.providerSubject(), existing.encryptedUpstreamRefreshToken(),
                    RefreshTableConstants.STATUS_REVOKED, existing.tokenFamilyId(), existing.rotatedFrom(), existing.replacedBy(),
                    existing.rotatedAt(), existing.issuedAt(), existing.expiresAt(), existing.ttl()));
        }
    }

    @Override
    public void handleReplay(String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            return;
        }
        RefreshTokenRecord record = lookupByHash(hashToken(refreshToken));
        if (record != null) {
            log.warn("Refresh token replay detected; revoking family tokenFamilyId={} userId={}", record.tokenFamilyId(), record.userId());
            revokeFamily(record.tokenFamilyId());
        }
    }

    @Override
    public String getUpstreamRefreshToken(String userId, String provider) {
        if (userId == null || userId.isEmpty() || provider == null || provider.isEmpty()) {
            return null;
        }
        RefreshTokenRecord best = queryBestUpstreamRefresh(provider + "#" + userId);
        if (best == null || best.encryptedUpstreamRefreshToken() == null || best.encryptedUpstreamRefreshToken().isEmpty()) {
            return null;
        }
        return best.encryptedUpstreamRefreshToken();
    }

    @Override
    public void updateUpstreamRefreshForToken(String mopRefreshToken, String newUpstreamRefresh) {
        if (mopRefreshToken == null || mopRefreshToken.isEmpty()
                || newUpstreamRefresh == null || newUpstreamRefresh.isEmpty()) {
            return;
        }
        String id = hashToId.get(hashToken(mopRefreshToken));
        if (id == null) {
            log.warn("updateUpstreamRefreshForToken: no row found for MOP token hash");
            return;
        }
        updateUpstream(id, newUpstreamRefresh);
    }

    @Override
    public void updateUpstreamRefreshForToken(String refreshTokenId, String providerUserId, String newUpstreamRefresh) {
        if (refreshTokenId == null || refreshTokenId.isEmpty() || providerUserId == null || providerUserId.isEmpty()
                || newUpstreamRefresh == null || newUpstreamRefresh.isEmpty()) {
            return;
        }
        RefreshTokenRecord existing = byId.get(refreshTokenId);
        if (existing == null || !providerUserId.equals(existing.providerUserId())) {
            log.warn("updateUpstreamRefreshForToken: row not found by primary key refreshTokenId={} providerUserId={}", refreshTokenId, providerUserId);
            return;
        }
        updateUpstream(refreshTokenId, newUpstreamRefresh);
        log.debug("updateUpstreamRefreshForToken: updated upstream token for refreshTokenId={}", refreshTokenId);
    }

    @Override
    public void updateUpstreamRefreshForAllRowsWithUserAndProvider(String userId, String provider, String newUpstreamRefresh) {
        if (userId == null || userId.isEmpty() || provider == null || provider.isEmpty()
                || newUpstreamRefresh == null || newUpstreamRefresh.isEmpty()) {
            return;
        }
        Set<String> ids = userProviderToIds.get(provider + "#" + userId);
        if (ids == null || ids.isEmpty()) {
            log.debug("updateUpstreamRefreshForAllRowsWithUserAndProvider: no rows for userId={} provider={}", userId, provider);
            return;
        }
        int updated = 0;
        for (String id : ids) {
            RefreshTokenRecord existing = byId.get(id);
            if (existing != null && RefreshTableConstants.STATUS_ACTIVE.equals(existing.status())) {
                updateUpstream(id, newUpstreamRefresh);
                updated++;
            }
        }
        log.info("updateUpstreamRefreshForAllRowsWithUserAndProvider: updated {} row(s) for userId={} provider={}",
                updated, userId, provider);
    }

    @Override
    public void nullifyLegacyUpstreamColumnForUserProvider(String userId, String provider) {
        if (userId == null || userId.isEmpty() || provider == null || provider.isEmpty()) {
            return;
        }
        Set<String> ids = userProviderToIds.get(provider + "#" + userId);
        if (ids == null || ids.isEmpty()) {
            return;
        }
        int cleared = 0;
        for (String id : ids) {
            RefreshTokenRecord existing = byId.get(id);
            if (existing != null && RefreshTableConstants.STATUS_ACTIVE.equals(existing.status())
                    && existing.encryptedUpstreamRefreshToken() != null && !existing.encryptedUpstreamRefreshToken().isEmpty()) {
                updateUpstream(id, "");
                cleared++;
            }
        }
        if (cleared > 0) {
            log.info("event=legacy_upstream_column_nullified user_id={} provider={} cleared_rows={}", userId, provider, cleared);
        }
    }

    private void updateUpstream(String id, String newUpstreamRefresh) {
        byId.computeIfPresent(id, (k, existing) -> new RefreshTokenRecord(
                existing.refreshTokenId(), existing.providerUserId(), existing.userId(), existing.clientId(),
                existing.provider(), existing.audience(), existing.providerSubject(), newUpstreamRefresh,
                existing.status(), existing.tokenFamilyId(), existing.rotatedFrom(), existing.replacedBy(),
                existing.rotatedAt(), existing.issuedAt(), existing.expiresAt(), existing.ttl()));
    }

    private RefreshTokenRecord lookupByHash(String hash) {
        String id = hashToId.get(hash);
        return id == null ? null : byId.get(id);
    }

    /** In-memory equivalent of {@code RefreshTokenStoreDynamodbHelpers.queryLatestActiveInFamily}. */
    private RefreshTokenRecord queryLatestActiveInFamily(String tokenFamilyId) {
        if (tokenFamilyId == null || tokenFamilyId.isEmpty()) {
            return null;
        }
        Set<String> ids = familyToIds.get(tokenFamilyId);
        if (ids == null || ids.isEmpty()) {
            return null;
        }
        long now = System.currentTimeMillis() / 1000;
        RefreshTokenRecord best = null;
        for (String id : ids) {
            RefreshTokenRecord r = byId.get(id);
            if (r == null || !RefreshTableConstants.STATUS_ACTIVE.equals(r.status())) {
                continue;
            }
            if (r.expiresAt() > 0 && now > r.expiresAt()) {
                continue;
            }
            if (best == null || r.issuedAt() > best.issuedAt()) {
                best = r;
            }
        }
        return best;
    }

    /** In-memory equivalent of {@code RefreshTokenStoreDynamodbHelpers.queryBestUpstreamRefresh}. */
    private RefreshTokenRecord queryBestUpstreamRefresh(String providerUserId) {
        Set<String> ids = userProviderToIds.get(providerUserId);
        if (ids == null || ids.isEmpty()) {
            return null;
        }
        long now = System.currentTimeMillis() / 1000;
        RefreshTokenRecord best = null;
        for (String id : ids) {
            RefreshTokenRecord r = byId.get(id);
            if (r == null) {
                continue;
            }
            if (r.expiresAt() > 0 && now > r.expiresAt()) {
                continue;
            }
            if (RefreshTableConstants.STATUS_REVOKED.equals(r.status())) {
                continue;
            }
            if (r.encryptedUpstreamRefreshToken() == null || r.encryptedUpstreamRefreshToken().isEmpty()) {
                continue;
            }
            if (best == null || r.issuedAt() > best.issuedAt()) {
                best = r;
            }
        }
        return best;
    }

    private static void indexAdd(ConcurrentHashMap<String, Set<String>> index, String key, String id) {
        index.computeIfAbsent(key, k -> ConcurrentHashMap.newKeySet()).add(id);
    }
}
