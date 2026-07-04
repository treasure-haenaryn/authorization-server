package com.haenaryn.authserver.domain.token;

import com.haenaryn.authserver.domain.user.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Refresh Token 발급/Rotation/재사용감지 로직. {@link RefreshTokenRepository}와
 * {@link RefreshTokenHistoryRepository}에만 의존해서, Spring Authorization Server의
 * 내부 구현(OAuth2TokenGenerator, OAuth2AuthorizationService 등)과 독립적으로
 * 단위 테스트할 수 있게 설계했다.
 *
 * <p><b>알아둘 점</b>: 이 서비스를 Spring Authorization Server의 실제 refresh_token
 * grant 처리 파이프라인에 연결하는 작업은 별도 이터레이션에서 진행한다 (Phase3 계획
 * 문서의 "중요한 미결 사항" 참고). 지금은 발급/교체/재사용감지라는 핵심 로직 자체의
 * 정확성만 담보한다.</p>
 */
@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenHistoryRepository refreshTokenHistoryRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                                RefreshTokenHistoryRepository refreshTokenHistoryRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshTokenHistoryRepository = refreshTokenHistoryRepository;
    }

    /**
     * 로그인(Authorization Code Flow 최초 진입) 시점의 최초 발급. 새 {@code family_id}를
     * 만든다 — 이 값이 이후 모든 rotate()의 기준이 된다.
     */
    @Transactional
    public IssuedRefreshToken issueInitial(User user, String clientId, String deviceInfo,
                                            String ipAddress, Duration ttl) {
        String familyId = UUID.randomUUID().toString();
        IssuedRefreshToken issued = createAndSaveToken(user, clientId, familyId, deviceInfo, ipAddress, ttl);

        refreshTokenHistoryRepository.save(RefreshTokenHistory.builder()
                .user(user)
                .familyId(familyId)
                .newToken(issued.entity())
                .eventType(RefreshTokenEventType.ISSUED)
                .ipAddress(ipAddress)
                .deviceInfo(deviceInfo)
                .build());

        return issued;
    }

    /**
     * 정상적인 refresh token 교체(rotation). 제시된 원문 토큰을 해시해 DB에서 조회하고:
     * <ul>
     *     <li>이미 폐기된 토큰이면 → 재사용 감지로 판단, family_id 체인 전체를 즉시
     *     폐기하고 {@link RefreshTokenReuseDetectedException}을 던진다.</li>
     *     <li>만료됐으면 → {@link InvalidRefreshTokenException}.</li>
     *     <li>정상이면 → 기존 토큰을 폐기(rotated)하고, 같은 family_id로 새 토큰을 발급한다.</li>
     * </ul>
     */
    @Transactional
    public IssuedRefreshToken rotate(String presentedRawToken, String deviceInfo, String ipAddress, Duration ttl) {
        String presentedHash = TokenHasher.sha256(presentedRawToken);
        RefreshToken previous = refreshTokenRepository.findByTokenHash(presentedHash)
                .orElseThrow(() -> new InvalidRefreshTokenException("존재하지 않는 refresh token입니다."));

        if (previous.isRevoked()) {
            handleReuseDetected(previous, deviceInfo, ipAddress);
            throw new RefreshTokenReuseDetectedException(previous.getFamilyId());
        }

        if (previous.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new InvalidRefreshTokenException("만료된 refresh token입니다.");
        }

        previous.revoke("system-rotated");
        refreshTokenRepository.save(previous);

        IssuedRefreshToken issued = createAndSaveToken(
                previous.getUser(), previous.getClientId(), previous.getFamilyId(), deviceInfo, ipAddress, ttl
        );

        refreshTokenHistoryRepository.save(RefreshTokenHistory.builder()
                .user(previous.getUser())
                .familyId(previous.getFamilyId())
                .previousToken(previous)
                .newToken(issued.entity())
                .eventType(RefreshTokenEventType.ROTATED)
                .ipAddress(ipAddress)
                .deviceInfo(deviceInfo)
                .build());

        return issued;
    }

    /**
     * 이미 폐기된 토큰의 재사용 = 탈취 의심. family_id 하나로 체인 전체를 한 번의
     * UPDATE로 폐기한다 (Phase2에서 설계한 전략 — previous/new 포인터 재귀 추적 대신
     * family_id 기준 벌크 처리).
     */
    private void handleReuseDetected(RefreshToken reusedToken, String deviceInfo, String ipAddress) {
        refreshTokenRepository.bulkRevokeByFamilyId(
                reusedToken.getFamilyId(), LocalDateTime.now(), "system-reuse-detected"
        );

        refreshTokenHistoryRepository.save(RefreshTokenHistory.builder()
                .user(reusedToken.getUser())
                .familyId(reusedToken.getFamilyId())
                .previousToken(reusedToken)
                .eventType(RefreshTokenEventType.REUSE_DETECTED)
                .ipAddress(ipAddress)
                .deviceInfo(deviceInfo)
                .build());
    }

    private IssuedRefreshToken createAndSaveToken(User user, String clientId, String familyId,
                                                   String deviceInfo, String ipAddress, Duration ttl) {
        String rawToken = TokenHasher.generateOpaqueToken();

        RefreshToken entity = refreshTokenRepository.save(RefreshToken.builder()
                .tokenHash(TokenHasher.sha256(rawToken))
                .familyId(familyId)
                .user(user)
                .clientId(clientId)
                .deviceInfo(deviceInfo)
                .ipAddress(ipAddress)
                .expiresAt(LocalDateTime.now().plus(ttl))
                .build());

        return new IssuedRefreshToken(rawToken, entity);
    }
}
