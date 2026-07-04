package com.haenaryn.authserver.controller;

import com.haenaryn.authserver.cache.RedisKeys;
import com.haenaryn.authserver.domain.audit.AuditEventType;
import com.haenaryn.authserver.domain.audit.AuditLogService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * JWT 기반 로그아웃 엔드포인트. Access Token 블랙리스트 등록 + 같은 세션의
 * Refresh Token family 전체 폐기까지 처리한다.
 */
@RestController
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String JTI_CLAIM = "jti";

    private final OAuth2AuthorizationService authorizationService;
    private final RedisTemplate<String, String> redisTemplate;
    private final AuditLogService auditLogService;

    public AuthController(OAuth2AuthorizationService authorizationService,
                           RedisTemplate<String, String> redisTemplate,
                           AuditLogService auditLogService) {
        this.authorizationService = authorizationService;
        this.redisTemplate = redisTemplate;
        this.auditLogService = auditLogService;
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<Void> logout(@RequestHeader(value = "Authorization", required = false) String authorizationHeader) {
        String token = extractBearerToken(authorizationHeader);
        if (token == null) {
            return ResponseEntity.badRequest().build();
        }

        OAuth2Authorization authorization = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null || authorization.getAccessToken() == null) {
            return ResponseEntity.noContent().build();
        }

        Map<String, Object> claims = authorization.getAccessToken().getClaims();
        String jti = claims != null && claims.get(JTI_CLAIM) instanceof String value ? value : null;
        if (jti != null) {
            try {
                redisTemplate.opsForValue().set(RedisKeys.blacklist(jti), "1", RedisKeys.BLACKLIST_TTL);
                log.info("Access Token 블랙리스트 등록 완료: jti={}", jti);
            } catch (Exception e) {
                log.warn("Redis 장애로 블랙리스트 등록 실패, fail-open으로 응답만 성공 처리: jti={}", jti, e);
            }
        } else {
            log.warn("Access Token에서 jti 클레임을 찾을 수 없어 블랙리스트 등록을 건너뜀");
        }

        authorizationService.remove(authorization);
        auditLogService.record(AuditEventType.LOGOUT, authorization.getPrincipalName(), null);

        return ResponseEntity.noContent().build();
    }

    private String extractBearerToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)) {
            return authorizationHeader.substring(BEARER_PREFIX.length());
        }
        return null;
    }
}
