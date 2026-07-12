# postgres:16 이미지는 pg_partman을 기본 포함하지 않는다.
# postgres 공식 이미지에는 PGDG apt 저장소가 이미 설정돼 있어서
# postgresql-16-partman 패키지를 apt로 바로 설치할 수 있다.
FROM postgres:16

RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-16-partman \
    && rm -rf /var/lib/apt/lists/*
