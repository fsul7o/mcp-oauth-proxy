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

import io.athenz.mop.service.RefreshLockStore;
import io.athenz.mop.store.MemoryStoreQualifier;
import jakarta.enterprise.context.ApplicationScoped;
import java.lang.invoke.MethodHandles;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * In-memory {@link RefreshLockStore} for {@code server.token-store.implementation: memory}.
 * Single-JVM-heap equivalent of {@code RefreshLockStoreDynamodbImpl}: a {@link ConcurrentHashMap}
 * keyed on lock key, with atomic acquire/release. Not persisted across restarts.
 */
@ApplicationScoped
@MemoryStoreQualifier
public class RefreshLockStoreInMemoryImpl implements RefreshLockStore {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private record LockEntry(String owner, long expiresAt) {}

    private final ConcurrentHashMap<String, LockEntry> locks = new ConcurrentHashMap<>();

    @Override
    public boolean tryAcquire(String lockKey, String owner, long expiresAt) {
        if (lockKey == null || lockKey.isEmpty() || owner == null || owner.isEmpty()) {
            return false;
        }
        long now = System.currentTimeMillis() / 1000;
        boolean[] acquired = {false};
        locks.compute(lockKey, (key, existing) -> {
            if (existing == null || existing.expiresAt() < now) {
                acquired[0] = true;
                return new LockEntry(owner, expiresAt);
            }
            return existing;
        });
        if (acquired[0]) {
            log.debug("Refresh lock acquired (memory) lockKey={} owner={}", lockKey, owner);
        } else {
            log.debug("Refresh lock not acquired (memory, held by another) lockKey={}", lockKey);
        }
        return acquired[0];
    }

    @Override
    public void release(String lockKey, String owner) {
        if (lockKey == null || lockKey.isEmpty()) {
            return;
        }
        boolean[] released = {false};
        locks.computeIfPresent(lockKey, (key, existing) -> {
            if (Objects.equals(existing.owner(), owner)) {
                released[0] = true;
                return null;
            }
            return existing;
        });
        if (released[0]) {
            log.debug("Refresh lock released (memory) lockKey={} owner={}", lockKey, owner);
        } else {
            log.debug("Refresh lock release skipped (memory, not owner or already gone) lockKey={}", lockKey);
        }
    }
}
