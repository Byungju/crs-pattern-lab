# 소스 저장소 (clone 경로 / 버전 고정)

이 랩에서 `src/` 및 `coreruleset/` 로 clone 한 저장소 정보를 기록한다.
재현 시에는 아래 clone 명령 뒤에 commit 을 checkout 하면 동일한 버전을 얻는다.

## 요약

| 구성요소 | GitHub 저장소 | 브랜치 | 고정 commit | 버전 |
|----------|---------------|--------|-------------|------|
| nginx | <https://github.com/nginx/nginx> | `master` | `ef0aa967dce9d30b824d4c839d3579d2a17e0666` | 1.31.7 |
| libmodsecurity | <https://github.com/owasp-modsecurity/ModSecurity> | `v3/master` | `2dada4ce3d44f438519fa5f1cd52c31848da0589` | 3.0.16 |
| ModSecurity-nginx | <https://github.com/owasp-modsecurity/ModSecurity-nginx> | `master` | `6b47cbb01c002ece5e8e5e0be14d34df16d8e479` | 1.0.4 |
| OWASP CRS | <https://github.com/coreruleset/coreruleset> | `main` | `8d060761d2215bea3ce1fd6e4b611ad2e0641a64` | 4.30.0-dev |

> `git describe` 기준:
> nginx `release-1.31.6-2-gef0aa967d`,
> ModSecurity `v3.0.16-2-g2dada4ce`,
> CRS `v4.29.0-17-g8d060761d`

## clone 명령

```bash
export LAB=/home/ubuntu/web_security
mkdir -p "$LAB/src" && cd "$LAB/src"

# nginx
git clone https://github.com/nginx/nginx.git
git -C nginx checkout ef0aa967dce9d30b824d4c839d3579d2a17e0666

# libmodsecurity (v3)
git clone https://github.com/owasp-modsecurity/ModSecurity.git
git -C ModSecurity checkout 2dada4ce3d44f438519fa5f1cd52c31848da0589

# nginx 커넥터
git clone https://github.com/owasp-modsecurity/ModSecurity-nginx.git
git -C ModSecurity-nginx checkout 6b47cbb01c002ece5e8e5e0be14d34df16d8e479

# OWASP CRS
cd "$LAB"
git clone https://github.com/coreruleset/coreruleset.git
git -C coreruleset checkout 8d060761d2215bea3ce1fd6e4b611ad2e0641a64
```

## ModSecurity submodule

libmodsecurity 는 configure 시 아래 submodule 의 존재를 검사한다.
비어 있으면 에러가 발생하므로 먼저 초기화한다.

```bash
cd "$LAB/src/ModSecurity"
git submodule update --init --recursive others/libinjection others/mbedtls
```

- `others/libinjection` : <https://github.com/libinjection/libinjection.git>
- `others/mbedtls` : <https://github.com/Mbed-TLS/mbedtls.git>

## 참고

- nginx 저장소는 top-level `configure` 가 없고 **`auto/configure`** 를 사용한다.
- 배포판 패키지로 구성하는 방법은 [02-package-install.md](02-package-install.md) 참고.
- 빌드 절차는 [01-source-build.md](01-source-build.md) 참고.
