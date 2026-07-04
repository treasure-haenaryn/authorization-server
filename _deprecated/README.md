# 이 폴더는 무엇인가

2026-07-03, Claude와의 설계 리뷰 중 발견: `RefreshTokenService`가 `HybridOAuth2AuthorizationService`와
**같은 책임(발급/rotation/재사용감지)을 중복 구현**하고 있었고, 실제 `/oauth2/token` 파이프라인은
`AuthorizationServiceConfig`가 `HybridOAuth2AuthorizationService`만 빈으로 등록하므로
`RefreshTokenService`는 어디서도 호출되지 않는 죽은 코드였음.

## 왜 "통합"이 아니라 "제거"를 택했나

`RefreshTokenService.issueInitial()`/`rotate()`는 토큰 원문 자체를 자기가
`TokenHasher.generateOpaqueToken()`으로 직접 생성하는 모델. 반면 실제 파이프라인
(`HybridOAuth2AuthorizationService.save()`)에서는 토큰 값이 이미 Spring Authorization
Server의 `OAuth2TokenGenerator`가 만들어서 `OAuth2Authorization` 객체 안에 들어있는
상태로 넘어옴 — 우리는 새로 생성하는 게 아니라 이미 만들어진 값의 해시만 기록하는 입장.

**두 클래스는 "누가 토큰 원문을 발급하는 주체인가"부터 설계가 다르다.** 그래서 `Hybrid`가
`RefreshTokenService`를 호출하도록 만드는 것보다, 이제 역할이 끝난 `RefreshTokenService`를
제거하는 게 맞는 선택.

## 이 폴더의 파일들

- `RefreshTokenService.java` — 위 이유로 미사용
- `IssuedRefreshToken.java` — `RefreshTokenService`의 리턴 타입, 함께 미사용
- `InvalidRefreshTokenException.java`, `RefreshTokenReuseDetectedException.java` —
  `RefreshTokenService`에서만 사용되던 예외. `Hybrid`는 예외를 던지는 대신 `null`을
  리턴해 프레임워크가 `invalid_grant`로 처리하게 하는 방식이라 이 예외들도 불필요해짐.
- `RefreshTokenServiceTest.java` — 위 서비스의 단위테스트. 통과해도 실제 운영 경로
  (`HybridOAuth2AuthorizationServiceTest`가 검증하는 경로)와는 무관했음.

## 조치 필요

로컬에서 `./gradlew build`로 컴파일 이상 없음을 1차 확인한 뒤, 이 폴더 자체를 삭제하고
git에서도 `git rm -r _deprecated` 처리할 것. 그전까지는 참고용으로만 보관.
