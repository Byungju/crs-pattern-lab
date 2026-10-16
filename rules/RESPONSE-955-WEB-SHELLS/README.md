# RESPONSE-955-WEB-SHELLS.conf — 쉽게 읽는 분석

> 이 문서는 `RESPONSE-955-WEB-SHELLS.conf` 룰을 "기초 → 룰 → 공격 예제 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/RESPONSE-955-WEB-SHELLS.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 변수(예: `ARGS`, `REQUEST_URI`, `REQUEST_HEADERS`, `REQUEST_FILENAME`)를 연산자로 검사하고 action 을 정한다.
- **phase**: 1=요청 헤더, 2=요청 본문/파라미터, 3/4=응답, 5=로깅.
- **어노말리 스코어**: 룰은 점수만 쌓고, phase 2 끝(또는 phase 4 끝)에 `949110`/`959110` 이 임계값을 넘으면 차단.
- **paranoia level(PL)**: 1~4. 구간 사이 게이팅 룰(`…011`~`…018`)이 있다.

> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> 응답에서 웹셸/백도어 흔적을 탐지한다.

## 2. 룰

> 상세 설명은 룰 id별 `<id>.md` 파일에 있다.

| ID | phase | PL | severity | 메시지 |
|----|-------|----|----------|--------|
| [955010](../../modsecurity/paranoia-gating.md) | 4 | - | - | (게이팅) PL 구간 제어 |
| [955011](../../modsecurity/paranoia-gating.md) | 3 | - | - | (게이팅) PL 구간 제어 |
| [955012](../../modsecurity/paranoia-gating.md) | 4 | - | - | (게이팅) PL 구간 제어 |
| [955100](955100.md) | 4 | 1 | CRITICAL | PHP Web shell detected |
| [955110](955110.md) | 4 | 1 | CRITICAL | r57 web shell |
| [955120](955120.md) | 4 | 1 | CRITICAL | WSO web shell |
| [955130](955130.md) | 4 | 1 | CRITICAL | b4tm4n web shell |
| [955140](955140.md) | 4 | 1 | CRITICAL | Mini Shell web shell |
| [955150](955150.md) | 4 | 1 | CRITICAL | Ashiyane web shell |
| [955160](955160.md) | 4 | 1 | CRITICAL | Symlink_Sa web shell |
| [955170](955170.md) | 4 | 1 | CRITICAL | CasuS web shell |
| [955180](955180.md) | 4 | 1 | CRITICAL | GRP WebShell |
| [955190](955190.md) | 4 | 1 | CRITICAL | NGHshell web shell |
| [955200](955200.md) | 4 | 1 | CRITICAL | SimAttacker web shell |
| [955210](955210.md) | 4 | 1 | CRITICAL | Unknown web shell |
| [955220](955220.md) | 4 | 1 | CRITICAL | lama\ |
| [955230](955230.md) | 4 | 1 | CRITICAL | lostDC web shell |
| [955240](955240.md) | 4 | 1 | CRITICAL | Unknown web shell |
| [955250](955250.md) | 4 | 1 | CRITICAL | Unknown web shell |
| [955260](955260.md) | 4 | 1 | CRITICAL | Ru24PostWebShell web shell |
| [955270](955270.md) | 4 | 1 | CRITICAL | s72 Shell web shell |
| [955280](955280.md) | 4 | 1 | CRITICAL | PhpSpy web shell |
| [955290](955290.md) | 4 | 1 | CRITICAL | g00nshell web shell |
| [955300](955300.md) | 4 | 1 | CRITICAL | PuNkHoLic shell web shell |
| [955310](955310.md) | 4 | 1 | CRITICAL | azrail web shell |
| [955320](955320.md) | 4 | 1 | CRITICAL | SmEvK_PaThAn Shell web shell |
| [955330](955330.md) | 4 | 1 | CRITICAL | Shell I web shell |
| [955340](955340.md) | 4 | 1 | CRITICAL | b374k m1n1 web shell |
| [955400](955400.md) | 4 | 1 | CRITICAL | ASP Web shell detected |
| [955013](../../modsecurity/paranoia-gating.md) | 3 | - | - | (게이팅) PL 구간 제어 |
| [955014](../../modsecurity/paranoia-gating.md) | 4 | - | - | (게이팅) PL 구간 제어 |
| [955350](955350.md) | 4 | 2 | CRITICAL | webadmin.php file manager |
| [955015](../../modsecurity/paranoia-gating.md) | 3 | - | - | (게이팅) PL 구간 제어 |
| [955016](../../modsecurity/paranoia-gating.md) | 4 | - | - | (게이팅) PL 구간 제어 |
| [955017](../../modsecurity/paranoia-gating.md) | 3 | - | - | (게이팅) PL 구간 제어 |
| [955018](../../modsecurity/paranoia-gating.md) | 4 | - | - | (게이팅) PL 구간 제어 |

---

## 3. 공격 예제 및 실측

| ID | 공격 예제(요청) | HTTP |
|----|------------------|------|
| [955100](955100.md) | `/leak_shell.html` | 200대 |

> 그 외 룰은 nginx 도달 불가/조건 필요라 `tests/<id>.sh` 에서 SKIP 처리했다. (PL 게이팅 룰은 테스트에서 제외)

---

## 4. 흐름 / 관계

- 매칭된 룰이 점수를 누적하고, 실제 차단은 **`949110`(요청)/`959110`(응답)** 이 수행한다.
- 파일은 PL 구간으로 나뉘고, 구간 사이 게이팅 룰이 낮은 PL 에서 하위 구간을 건너뛴다.

---

## 5. 검증 (테스트 하네스)

```
tests/
├── lib.sh · verify.sh · run-all.sh   # 범용 하네스
├── cases.tsv                         # 룰 id별 공격 예제
├── <rule-id>.sh                      # 룰 id별 개별 실행
└── (로그: ../../../logs/local_test/<파일명>/)
```

```bash
cd rules/RESPONSE-955-WEB-SHELLS/tests
./run-all.sh      # 전체
./<rule-id>.sh   # 개별
```

로그: `logs/local_test/RESPONSE-955-WEB-SHELLS/`

---

## 6. 참고

- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 생성 도구: `tools/gen_rule_docs.py`, `tools/make_harness.sh`
- 룰 원본: `coreruleset/rules/RESPONSE-955-WEB-SHELLS.conf`
