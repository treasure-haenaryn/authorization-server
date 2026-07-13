package com.haenaryn.authserver.domain.outbox;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SecurityEventOutboxRepository extends JpaRepository<SecurityEventOutbox, Long> {

    /** 향후 relay가 오래된 순으로 미전송 이벤트를 꺼내갈 때 사용. */
    List<SecurityEventOutbox> findAllByStatusOrderByCreatedAtAsc(OutboxStatus status);
}
