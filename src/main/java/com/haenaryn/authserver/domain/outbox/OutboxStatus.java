package com.haenaryn.authserver.domain.outbox;

/** 아웃박스 이벤트 전송 상태. relay 구현 전까지는 항상 PENDING으로 남는다. */
public enum OutboxStatus {
    PENDING,
    PUBLISHED,
    FAILED
}
