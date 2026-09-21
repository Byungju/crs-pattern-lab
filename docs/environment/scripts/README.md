# scripts

환경 구성을 자동화하는 참조용 스크립트 사본이다.
원본은 랩 루트(`$LAB/`)에 위치하며, 이 디렉토리는 문서화/보관 목적이다.

| 스크립트 | 역할 |
|----------|------|
| `build.sh` | 의존성 설치 + libmodsecurity/nginx(+커넥터) 소스 빌드 → `install/` 설치 |
| `setup-config.sh` | CRS 배치 + `modsecurity.conf` / `nginx.conf` 생성 |

## 실행 위치 주의

두 스크립트는 **자기 자신의 위치를 기준으로 랩 루트를 계산**한다.

```bash
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$ROOT_DIR/src"        # build.sh
CRS_SRC="$ROOT_DIR/coreruleset" # setup-config.sh
```

따라서 아래 디렉토리 구조의 **루트에 두고 실행**해야 한다.

```
$LAB/
├── build.sh              # <- 여기
├── setup-config.sh       # <- 여기
├── src/                  # nginx, ModSecurity, ModSecurity-nginx
├── coreruleset/
└── install/
```

이 문서 디렉토리에서 그대로 실행하면 `src/`, `coreruleset/` 를 찾지 못한다.
사용 시 랩 루트로 복사한 뒤 실행한다.

```bash
cp build.sh setup-config.sh "$LAB/"
cd "$LAB"
./build.sh
./setup-config.sh
```

## 사용법 요약

```bash
./build.sh [--no-deps] [--only-modsec] [--only-nginx] [--clean] [-j N]
./setup-config.sh [--no-nginx]
```

자세한 설명은 [01-source-build.md](../01-source-build.md) 참고.

## 소스 버전

빌드 대상 저장소와 고정 commit 은 [00-sources.md](../00-sources.md) 참고.
