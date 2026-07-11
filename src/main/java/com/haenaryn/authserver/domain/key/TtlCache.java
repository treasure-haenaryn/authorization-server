package com.haenaryn.authserver.domain.key;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;

/** 짧은 TTL로 값을 캐싱하는 최소 구현 (double-checked locking). */
final class TtlCache<T> {

    private final Duration ttl;
    private final Supplier<T> loader;

    private volatile T value;
    private volatile Instant loadedAt = Instant.MIN;

    TtlCache(Duration ttl, Supplier<T> loader) {
        this.ttl = ttl;
        this.loader = loader;
    }

    T get() {
        Instant now = Instant.now();
        if (isValid(now)) {
            return value;
        }
        synchronized (this) {
            if (isValid(now)) {
                return value;
            }
            value = loader.get();
            loadedAt = now;
            return value;
        }
    }

    private boolean isValid(Instant now) {
        return value != null && loadedAt.plus(ttl).isAfter(now);
    }
}
