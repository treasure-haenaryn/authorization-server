package com.haenaryn.authserver.domain.token;

/** 존재하지 않거나 만료된 refresh token으로 요청이 들어왔을 때. */
public class InvalidRefreshTokenException extends RuntimeException {

    public InvalidRefreshTokenException(String message) {
        super(message);
    }
}
