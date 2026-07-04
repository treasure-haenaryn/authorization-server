package com.haenaryn.authserver.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

/**
 * dev 프로파일에서만 동작 — Authorization Code Flow / Client Credentials Flow를 수동으로
 * 검증할 수 있도록 샘플 클라이언트 2개 등록
 */
@Configuration
@Profile("dev")
public class DevClientSeeder {

    @Bean
    public CommandLineRunner registerSampleClients(RegisteredClientRepository registeredClientRepository,
                                                     PasswordEncoder passwordEncoder,
                                                     AuthServerProperties properties) {
        return args -> {
            TokenSettings tokenSettings = TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(properties.token().accessTokenTtlMinutes()))
                    .refreshTokenTimeToLive(Duration.ofDays(properties.token().refreshTokenTtlDays()))
                    // 프레임워크 자체 refresh token 재사용 방지 옵션도 꺼서, RefreshTokenService의
                    // family_id 기반 Rotation과 책임이 겹치지 않게 한다 (이중 관리 방지).
                    .reuseRefreshTokens(false)
                    .build();

            registerIfAbsent(registeredClientRepository, "oidc-client", () ->
                    RegisteredClient.withId(UUID.randomUUID().toString())
                            .clientId("oidc-client")
                            .clientSecret(passwordEncoder.encode("secret"))
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                            .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                            .postLogoutRedirectUri("http://127.0.0.1:9000/")
                            .scope(OidcScopes.OPENID)
                            .scope(OidcScopes.PROFILE)
                            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                            .tokenSettings(tokenSettings)
                            .build()
            );

            // M2M 통신
            registerIfAbsent(registeredClientRepository, "event-service", () ->
                    RegisteredClient.withId(UUID.randomUUID().toString())
                            .clientId("event-service")
                            .clientSecret(passwordEncoder.encode("secret"))
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                            .scope("event:read")
                            .scope("event:write")
                            .tokenSettings(tokenSettings)
                            .build()
            );
        };
    }

    private void registerIfAbsent(RegisteredClientRepository repository, String clientId,
                                   java.util.function.Supplier<RegisteredClient> clientSupplier) {
        if (repository.findByClientId(clientId) == null) {
            repository.save(clientSupplier.get());
        }
    }
}
