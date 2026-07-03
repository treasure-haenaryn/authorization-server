package com.haenaryn.authserver.domain.token;

import com.haenaryn.authserver.domain.user.User;
import com.haenaryn.authserver.domain.user.UserRepository;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;

/**
 * authorization_code/access_token/id_token은 delegate(JDBC)에 위임하고, refresh_token만
 * 우리 refresh_tokens 테이블(해시 저장 + family_id 재사용 감지)로 관리한다.
 *
 * <p>설계 근거와 상세 동작은 Obsidian "Authorization Server/Phase3_작업계획" 문서 참고.</p>
 */
public class HybridOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationService delegate;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenHistoryRepository refreshTokenHistoryRepository;
    private final UserRepository userRepository;
    private final RegisteredClientRepository registeredClientRepository;

    public HybridOAuth2AuthorizationService(OAuth2AuthorizationService delegate,
                                             RefreshTokenRepository refreshTokenRepository,
                                             RefreshTokenHistoryRepository refreshTokenHistoryRepository,
                                             UserRepository userRepository,
                                             RegisteredClientRepository registeredClientRepository) {
        this.delegate = delegate;
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshTokenHistoryRepository = refreshTokenHistoryRepository;
        this.userRepository = userRepository;
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        delegate.save(authorization);
        syncRefreshTokenLedger(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
        refreshTokenRepository.bulkRevokeByFamilyId(authorization.getId(), LocalDateTime.now(), "system-authorization-removed");
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        // tokenType이 REFRESH_TOKEN이 아님이 명확하면 우리 테이블 조회 없이 바로 delegate.
        if (tokenType != null && !OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return delegate.findByToken(token, tokenType);
        }

        // REFRESH_TOKEN이거나 tokenType == null(GitHub #1926)인 경우만 우리 테이블 확인.
        String hash = TokenHasher.sha256(token);
        Optional<RefreshToken> ours = refreshTokenRepository.findByTokenHash(hash);

        if (ours.isEmpty()) {
            return delegate.findByToken(token, tokenType);
        }

        RefreshToken refreshToken = ours.get();

        if (refreshToken.isRevoked()) {
            handleReuseDetected(refreshToken, token, tokenType);
            return null;
        }

        if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            return null;
        }

        // 전체 OAuth2Authorization 원본은 여전히 delegate가 보유 — 우리 테이블은 검증용 원장.
        return delegate.findByToken(token, tokenType);
    }

    /** 재사용(탈취 의심) 감지 시 family_id 체인 전체 폐기 + delegate의 authorization도 제거. */
    private void handleReuseDetected(RefreshToken reusedToken, String token, OAuth2TokenType tokenType) {
        refreshTokenRepository.bulkRevokeByFamilyId(
                reusedToken.getFamilyId(), LocalDateTime.now(), "system-reuse-detected"
        );

        refreshTokenHistoryRepository.save(RefreshTokenHistory.builder()
                .user(reusedToken.getUser())
                .familyId(reusedToken.getFamilyId())
                .previousToken(reusedToken)
                .eventType(RefreshTokenEventType.REUSE_DETECTED)
                .build());

        OAuth2Authorization compromised = delegate.findByToken(token, tokenType);
        if (compromised != null) {
            delegate.remove(compromised);
        }
    }

    /** refresh_token이 포함된 authorization을 우리 원장에 기록/rotation 처리. */
    private void syncRefreshTokenLedger(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenToken = authorization.getRefreshToken();
        if (refreshTokenToken == null) {
            return;
        }

        String rawValue = refreshTokenToken.getToken().getTokenValue();
        String hash = TokenHasher.sha256(rawValue);

        if (refreshTokenRepository.findByTokenHash(hash).isPresent()) {
            return;
        }

        String familyId = authorization.getId();

        List<RefreshToken> previousActive = refreshTokenRepository.findAllByFamilyId(familyId).stream()
                .filter(t -> !t.isRevoked())
                .toList();
        previousActive.forEach(t -> {
            t.revoke("system-rotated");
            refreshTokenRepository.save(t);
        });

        User user = userRepository.findByEmail(authorization.getPrincipalName())
                .orElseThrow(() -> new IllegalStateException(
                        "User를 찾을 수 없습니다: principalName=" + authorization.getPrincipalName()
                ));

        RegisteredClient registeredClient = registeredClientRepository.findById(authorization.getRegisteredClientId());
        String clientId = registeredClient != null ? registeredClient.getClientId() : authorization.getRegisteredClientId();

        RefreshToken saved = refreshTokenRepository.save(RefreshToken.builder()
                .tokenHash(hash)
                .familyId(familyId)
                .user(user)
                .clientId(clientId)
                .expiresAt(LocalDateTime.ofInstant(refreshTokenToken.getToken().getExpiresAt(), ZoneId.systemDefault()))
                .build());

        refreshTokenHistoryRepository.save(RefreshTokenHistory.builder()
                .user(user)
                .familyId(familyId)
                .previousToken(previousActive.isEmpty() ? null : previousActive.getFirst())
                .newToken(saved)
                .eventType(previousActive.isEmpty() ? RefreshTokenEventType.ISSUED : RefreshTokenEventType.ROTATED)
                .build());
    }
}
