package com.haenaryn.authserver.domain.token;

import com.haenaryn.authserver.domain.user.User;
import com.haenaryn.authserver.domain.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;

/**
 * authorization_code/access_token/id_token은 delegate(JDBC)에 위임하고, refresh_token만
 * 우리 refresh_tokens 테이블로 관리한다.
 *
 * <p>설계 근거와 상세 동작은 Obsidian "Authorization Server/Phase3_작업계획" 문서 참고.</p>
 */
public class HybridOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(HybridOAuth2AuthorizationService.class);

    private static final String REDACTED_REFRESH_TOKEN_VALUE = "redacted";

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
    @Transactional
    public void save(OAuth2Authorization authorization) {
        // 원장 기록(원본 필요) 먼저, delegate에는 redacted 사본 저장.
        syncRefreshTokenLedger(authorization);
        delegate.save(sanitizeForDelegate(authorization));
    }

    @Override
    @Transactional
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
        refreshTokenRepository.bulkRevokeByFamilyId(authorization.getId(), LocalDateTime.now(), "system-authorization-removed");
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    @Override
    @Transactional
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        // REFRESH_TOKEN이 아님이 명확하면 짧은 회로로 바로 delegate.
        if (tokenType != null && !OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return delegate.findByToken(token, tokenType);
        }

        String hash = TokenHasher.sha256(token);
        Optional<RefreshToken> ours = refreshTokenRepository.findByTokenHash(hash);

        if (ours.isEmpty()) {
            return delegate.findByToken(token, tokenType);
        }

        RefreshToken refreshToken = ours.get();

        if (refreshToken.isRevoked()) {
            handleReuseDetected(refreshToken);
            return null;
        }

        if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            return null;
        }

        // delegate에는 redacted 값만 있으므로 family_id로 조회.
        return delegate.findById(refreshToken.getFamilyId());
    }

    /** 재사용(탈취 의심) 감지 시 family_id 체인 전체 폐기 + delegate의 authorization도 제거. */
    private void handleReuseDetected(RefreshToken reusedToken) {
        refreshTokenRepository.bulkRevokeByFamilyId(
                reusedToken.getFamilyId(), LocalDateTime.now(), "system-reuse-detected"
        );

        refreshTokenHistoryRepository.save(RefreshTokenHistory.builder()
                .user(reusedToken.getUser())
                .familyId(reusedToken.getFamilyId())
                .previousToken(reusedToken)
                .eventType(RefreshTokenEventType.REUSE_DETECTED)
                .build());

        OAuth2Authorization compromised = delegate.findById(reusedToken.getFamilyId());
        if (compromised != null) {
            delegate.remove(compromised);
        }
    }

    /** delegate에 저장할 사본을 만든다. refresh_token이 있으면 redacted 값으로 치환. */
    private OAuth2Authorization sanitizeForDelegate(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenToken = authorization.getRefreshToken();
        if (refreshTokenToken == null) {
            return authorization;
        }

        OAuth2RefreshToken original = refreshTokenToken.getToken();
        OAuth2RefreshToken redacted = new OAuth2RefreshToken(
                REDACTED_REFRESH_TOKEN_VALUE, original.getIssuedAt(), original.getExpiresAt()
        );

        return OAuth2Authorization.from(authorization)
                .token(redacted)
                .build();
    }

    /** refresh_token이 포함된 authorization을 우리 원장에 기록/rotation 처리. */
    private void syncRefreshTokenLedger(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenToken = authorization.getRefreshToken();
        if (refreshTokenToken == null) {
            return;
        }

        String rawValue = refreshTokenToken.getToken().getTokenValue();
        String hash = TokenHasher.sha256(rawValue);
        String familyId = authorization.getId();

        User user = userRepository.findByEmail(authorization.getPrincipalName())
                .orElseThrow(() -> new IllegalStateException(
                        "User를 찾을 수 없습니다: principalName=" + authorization.getPrincipalName()
                ));

        RegisteredClient registeredClient = registeredClientRepository.findById(authorization.getRegisteredClientId());
        String clientId = registeredClient != null ? registeredClient.getClientId() : authorization.getRegisteredClientId();

        // 이전 활성 토큰 폐기 (rotation 판단용 단건 확인 + 벌크 UPDATE).
        Optional<RefreshToken> previousActive = refreshTokenRepository.findFirstByFamilyIdAndRevokedFalse(familyId);
        if (previousActive.isPresent()) {
            refreshTokenRepository.bulkRevokeByFamilyId(familyId, LocalDateTime.now(), "system-rotated");
        }

        LocalDateTime expiresAt = LocalDateTime.ofInstant(refreshTokenToken.getToken().getExpiresAt(), ZoneId.systemDefault());

        // 원자적 삽입 (중복 시 조용히 무시, 생성된 id를 바로 반환받음).
        Optional<Long> newTokenId = refreshTokenRepository.insertIfAbsentReturningId(
                hash, familyId, user.getId(), clientId, expiresAt
        );
        if (newTokenId.isEmpty()) {
            log.debug("이미 기록된 refresh_token에 대한 중복 save() 호출 무시: familyId={}", familyId);
            return;
        }

        // 재조회 없이 프록시 참조로 FK만 연결.
        RefreshToken saved = refreshTokenRepository.getReferenceById(newTokenId.get());

        refreshTokenHistoryRepository.save(RefreshTokenHistory.builder()
                .user(user)
                .familyId(familyId)
                .previousToken(previousActive.orElse(null))
                .newToken(saved)
                .eventType(previousActive.isEmpty() ? RefreshTokenEventType.ISSUED : RefreshTokenEventType.ROTATED)
                .build());
    }
}
