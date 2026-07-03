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
 * {@link OAuth2AuthorizationService}의 실제 구현. authorization_code/access_token/id_token은
 * 공식 {@code JdbcOAuth2AuthorizationService}(delegate)에 그대로 위임하고, refresh_token만
 * 별도로 가로채서 우리 {@code refresh_tokens} 테이블(해시 저장 + family_id 재사용 감지)로
 * 관리한다.
 *
 * <p><b>왜 delegate 방식인가</b>: authorization_code/access_token/id_token은 원문 저장이
 * 요구사항 문서상 문제되지 않고(단명 토큰, 보안 요구사항 대상 아님), Spring이 이미 검증한
 * 스키마/구현을 그대로 쓰는 게 새로 구현하는 것보다 안전하다 (Phase2에서
 * {@code JdbcRegisteredClientRepository}를 채택한 것과 같은 논리). refresh_token만
 * "원문 미저장" 요구사항이 있어 이 부분만 우리 로직으로 대체한다.</p>
 *
 * <p><b>{@code findByToken}의 tokenType이 null로 들어올 수 있는 문제</b>
 * (spring-authorization-server GitHub #1926): {@code /oauth2/revoke} 등 일부 경로는
 * tokenType을 null로 넘긴다. 그래서 타입으로 분기하는 대신, 들어온 토큰 값을 항상 먼저
 * 우리 {@code refresh_tokens} 테이블에서 해시로 조회해보고, 있으면 refresh token으로
 * 처리하고 없으면 delegate로 넘기는 방식을 택했다. 타입 파라미터에 의존하지 않아 이
 * 알려진 이슈에 영향받지 않는다.</p>
 *
 * <p><b>{@code family_id}로 프레임워크의 {@code OAuth2Authorization.getId()}를 재사용</b>:
 * 같은 로그인 세션에서 rotate된 refresh token들은 프레임워크 내부적으로 항상 같은
 * authorization id를 유지한 채 저장(update)된다. 그래서 별도로 family_id를 발급하지 않고
 * 이 id를 그대로 family_id로 사용한다 — Phase2에서 설계했던 개념과 동일하되, 새 UUID를
 * 만들 필요 없이 프레임워크가 이미 관리하는 식별자를 재사용하는 것.</p>
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
        // authorization_code/access_token/id_token은 그대로 JDBC에 저장.
        // 이 시점에 refresh_token이 새로 포함돼 있으면 우리 테이블에도 별도 기록한다.
        delegate.save(authorization);
        syncRefreshTokenLedger(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
        // 이 authorization 소속 refresh token 체인 전체 폐기 (로그아웃, 관리자 강제 폐기 등)
        refreshTokenRepository.bulkRevokeByFamilyId(authorization.getId(), LocalDateTime.now(), "system-authorization-removed");
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        // tokenType이 null일 수 있어(GitHub #1926) 타입으로 분기하지 않고, 우리 테이블에
        // 먼저 존재하는지부터 확인한다. 여기 없으면 애초에 우리가 관리하는 refresh
        // token이 아니라는 뜻이므로 delegate로 넘긴다.
        String hash = TokenHasher.sha256(token);
        Optional<RefreshToken> ours = refreshTokenRepository.findByTokenHash(hash);

        if (ours.isEmpty()) {
            return delegate.findByToken(token, tokenType);
        }

        RefreshToken refreshToken = ours.get();

        if (refreshToken.isRevoked()) {
            handleReuseDetected(refreshToken, token, tokenType);
            return null; // 프레임워크는 null을 "유효하지 않은 토큰"으로 해석해 invalid_grant 응답
        }

        if (refreshToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            return null;
        }

        // 실제 OAuth2Authorization 객체(등록클라이언트/principal/다른 토큰들 포함)는
        // 여전히 JDBC delegate가 갖고 있다 — 우리 테이블은 보안 원장(ledger)일 뿐, 전체
        // 도메인 객체를 복제해서 들고 있지 않는다.
        return delegate.findByToken(token, tokenType);
    }

    /**
     * 재사용 감지 시: family_id 체인 전체 폐기 + JDBC에 남아있는 (탈취됐을 수 있는)
     * authorization도 함께 제거해 이중으로 방어한다.
     */
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

    private void syncRefreshTokenLedger(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshTokenToken = authorization.getRefreshToken();
        if (refreshTokenToken == null) {
            return; // client_credentials 등 refresh token이 없는 grant는 여기서 끝
        }

        String rawValue = refreshTokenToken.getToken().getTokenValue();
        String hash = TokenHasher.sha256(rawValue);

        if (refreshTokenRepository.findByTokenHash(hash).isPresent()) {
            return; // 같은 authorization을 여러 번 save()하며 이미 기록된 값 — 중복 방지
        }

        String familyId = authorization.getId();

        // 같은 family_id(=authorization id)로 이전에 활성 상태였던 토큰이 있다면
        // 이번 save()는 rotation을 의미한다 — 이전 것을 폐기 처리.
        List<RefreshToken> previousActive = refreshTokenRepository.findAllByFamilyId(familyId).stream()
                .filter(t -> !t.isRevoked())
                .toList();
        previousActive.forEach(t -> {
            t.revoke("system-rotated");
            refreshTokenRepository.save(t);
        });

        User user = userRepository.findByEmail(authorization.getPrincipalName())
                .orElseThrow(() -> new IllegalStateException(
                        "OAuth2Authorization의 principalName(" + authorization.getPrincipalName()
                                + ")에 해당하는 User를 찾을 수 없습니다."
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
