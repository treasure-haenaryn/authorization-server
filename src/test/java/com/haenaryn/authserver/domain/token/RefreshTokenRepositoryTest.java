package com.haenaryn.authserver.domain.token;

import com.haenaryn.authserver.domain.user.User;
import com.haenaryn.authserver.domain.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class RefreshTokenRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Test
    void save_and_findByTokenHash() {
        User user = userRepository.save(User.builder()
                .email("lee@haenaryn.com")
                .passwordHash("hashed-password")
                .build());

        RefreshToken token = RefreshToken.builder()
                .tokenHash("a".repeat(64)) // SHA-256 hex 길이(64) 형태만 맞춤
                .familyId(UUID.randomUUID().toString())
                .user(user)
                .clientId("test-client")
                .ipAddress("127.0.0.1")
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();

        refreshTokenRepository.save(token);

        Optional<RefreshToken> found = refreshTokenRepository.findByTokenHash("a".repeat(64));

        assertThat(found).isPresent();
        assertThat(found.get().isRevoked()).isFalse();
        assertThat(found.get().getUser().getEmail()).isEqualTo("lee@haenaryn.com");
        assertThat(found.get().getFamilyId()).isNotBlank();
    }

    @Test
    void revoke_marks_token_as_revoked_with_reason() {
        User user = userRepository.save(User.builder()
                .email("lee2@haenaryn.com")
                .passwordHash("hashed-password")
                .build());

        RefreshToken token = refreshTokenRepository.save(RefreshToken.builder()
                .tokenHash("b".repeat(64))
                .familyId(UUID.randomUUID().toString())
                .user(user)
                .clientId("test-client")
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build());

        token.revoke("admin");
        refreshTokenRepository.save(token);

        RefreshToken reloaded = refreshTokenRepository.findByTokenHash("b".repeat(64)).orElseThrow();
        assertThat(reloaded.isRevoked()).isTrue();
        assertThat(reloaded.getRevokedBy()).isEqualTo("admin");
        assertThat(reloaded.getRevokedAt()).isNotNull();
    }

    @Test
    void bulkRevokeByFamilyId_revokes_entire_chain_at_once() {
        User user = userRepository.save(User.builder()
                .email("lee3@haenaryn.com")
                .passwordHash("hashed-password")
                .build());

        String familyId = UUID.randomUUID().toString();
        LocalDateTime expiresAt = LocalDateTime.now().plusDays(7);

        // 같은 family_id로 v1 -> v2 -> v3 세 번 Rotation된 상황을 흉내냄
        refreshTokenRepository.save(RefreshToken.builder()
                .tokenHash("c1".repeat(32)).familyId(familyId).user(user)
                .clientId("test-client").expiresAt(expiresAt).build());
        refreshTokenRepository.save(RefreshToken.builder()
                .tokenHash("c2".repeat(32)).familyId(familyId).user(user)
                .clientId("test-client").expiresAt(expiresAt).build());
        // 다른 기기(별개 family_id)의 토큰은 영향받지 않아야 함
        String otherFamilyId = UUID.randomUUID().toString();
        refreshTokenRepository.save(RefreshToken.builder()
                .tokenHash("d1".repeat(32)).familyId(otherFamilyId).user(user)
                .clientId("test-client").expiresAt(expiresAt).build());

        int revokedCount = refreshTokenRepository.bulkRevokeByFamilyId(familyId, LocalDateTime.now(), "system-reuse-detected");

        assertThat(revokedCount).isEqualTo(2);

        List<RefreshToken> chain = refreshTokenRepository.findAllByFamilyId(familyId);
        assertThat(chain).allMatch(RefreshToken::isRevoked);

        List<RefreshToken> otherChain = refreshTokenRepository.findAllByFamilyId(otherFamilyId);
        assertThat(otherChain).noneMatch(RefreshToken::isRevoked);
    }
}
