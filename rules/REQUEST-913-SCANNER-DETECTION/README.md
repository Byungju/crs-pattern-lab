# REQUEST-913-SCANNER-DETECTION.conf — 쉽게 읽는 분석

> 이 문서는 **보안 스캐너 탐지** 파일을 "기초 → 룰 → 공격 예제 → 흐름 → 검증" 순서로 쉽게 설명한다.

분석 대상: `install/nginx/conf/crs/rules/REQUEST-913-SCANNER-DETECTION.conf` (CRS 4.30.0-dev)

---

## 0. 먼저 알아두면 좋은 ModSecurity 기초

- **룰**은 "무엇을(변수) / 어떻게(연산자)" 검사하고 "무엇을 할지(action)" 정한다.
  - 여기서는 변수 `REQUEST_HEADERS:User-Agent` 를, 연산자 `@pmFromFile` 로 검사한다.
- **phase**: 처리 단계(1=요청헤더, 2=요청본문, 3/4=응답, 5=로깅). 이 파일 탐지 룰은 **phase 1**.
- **`@pmFromFile`**: 파일에 들어 있는 **패턴들과 부분 일치**를 검사하는 연산자(정규식 아님).
- **어노말리 스코어**: 룰은 즉시 막지 않고 **점수만 쌓고**, phase 2 끝에 `949110` 이 임계값을 넘으면 403.
- **paranoia level(PL)**: 룰 민감도 단계(1~4). 파일은 PL 구간으로 나뉘고, 구간 사이에 게이팅 룰이 있다.

> 기초가 더 필요하면: [REQUEST-911 README](../REQUEST-911-METHOD-ENFORCEMENT/README.md),
> 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)

---

## 1. 한 줄 요약

> **요청의 `User-Agent` 가 알려진 보안 스캐너 목록(`scanners-user-agents.data`)에 있으면 403으로 차단한다.**

---

## 2. 룰

| ID | 유형 | 역할 |
|----|------|------|
| [913100](913100.md) | **탐지** | 스캐너 UA면 점수(CRITICAL=5) 누적 → `949110`이 403 |
| [913011](../../modsecurity/paranoia-gating.md)~[913018](../../modsecurity/paranoia-gating.md) | 게이팅 | paranoia level 에 따라 PL 구간 실행/건너뛰기 (탐지 아님) |
| `SecMarker END-...` | 표식 | 게이팅 룰이 점프할 목적지 |

- 실제 탐지 룰은 **`913100` 하나**이고, 나머지는 PL 제어 룰이다. (구조는 `REQUEST-911`과 동일)

---

## 3. 공격 예제 및 실측

"스캐너의 기본 User-Agent로 요청"이 공격 예제다.

| User-Agent | HTTP | 913100 | 949110 |
|------------|------|--------|--------|
| `sqlmap/1.7.2#stable` | **403** | 매칭 | 매칭 |
| `nikto/2.1.6` | **403** | 매칭 | 매칭 |
| `Nmap Scripting Engine` | **403** | 매칭 | 매칭 |
| `nuclei - Open Source vulnerability scanner` | **403** | 매칭 | 매칭 |
| `masscan/1.3` | **403** | 매칭 | 매칭 |
| `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` | 200 | 없음 | 없음 |
| `Googlebot/2.1 (+http://www.google.com/bot.html)` | 200 | 없음 | 없음 |

> 목록은 룰 폴더의 `scanners-user-agents.data`(245줄)에 있다. `@pmFromFile` 은 UA 안에
> 목록의 문자열이 **포함**되면 매칭한다(예: `sqlmap/1.7.2#stable` ⊃ `sqlmap`).

---

## 4. 흐름 / 관계

```
요청 도착 (User-Agent: sqlmap/1.7.2)
  phase 1 · 901-INITIALIZATION : 점수 변수 0으로 초기화
  phase 1 · 913100 : UA가 스캐너 목록에 매칭 → 점수 +5   (아직 차단 아님)
  phase 1 · 913013 : detection_pl(1) < 2 → END 로 점프 (PL2~4 skip)
  phase 2 끝 · 949110 : 점수 5 >= 임계값 5 → 403 차단
```

- 실제 차단은 **`949110`(다른 파일)** 이 수행한다.
- `913100` 은 "탐지 + 점수" 룰이고, 게이팅 룰군이 **어떤 PL 구간을 실행할지** 정한다.

### 4.1 연결고리: PL 게이트 · 점수 5 · 949 (헷갈리는 부분)

**`DETECTION_PARANOIA_LEVEL` 과 `913100` 의 관계**, 그리고 **점수 5의 출처**를 명확히 하면:

```
[PL 게이트] tx.detection_paranoia_level(기본 1, 901125)
              └─ 913011(@lt1) 통과 → 913100 실행됨
                 (만약 detection PL=0 이면 913011 이 END 로 점프 → 913100 실행 안 됨)
   │
   ▼
[913100] setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'
                                                        └─ 점수 5 는 여기서 옴
                                                           (901140 이 기본 5 로 설정한 변수)
   │
   ▼
[949052] blocking_paranoia_level(기본 1) >= 1 이면
         tx.blocking_inbound_anomaly_score += tx.inbound_anomaly_score_pl1
   │
   ▼
[949110] tx.blocking_inbound_anomaly_score >= tx.inbound_anomaly_score_threshold(기본 5)
         → deny → HTTP 403
```

핵심 정리:
- **`913100` 은 `tx.detection_paranoia_level >= 1` 일 때만 실행**된다(PL1 구간에 있음).
- **점수 5는 `913100`에 하드코딩된 게 아니라**, severity CRITICAL 에 매핑된
  **`tx.critical_anomaly_score`(=901140 기본 5)** 에서 온다.
- 실제 403 판정은 **`949110`(REQUEST-949-BLOCKING-EVALUATION.conf)** 이 한다.

> 전체 설명: [../../modsecurity/score-and-paranoia.md](../../modsecurity/score-and-paranoia.md)

---

## 5. 검증 (테스트 하네스)

```
tests/
├── lib.sh        # 테스트 nginx 기동, UA 요청, 913100/949110 카운트
├── verify.sh     # 룰 id별 검증 케이스
├── run-all.sh    # 전체 실행
├── 913100.sh
└── (로그: ../../../logs/local_test/REQUEST-913-SCANNER-DETECTION/)
```

```bash
cd rules/REQUEST-913-SCANNER-DETECTION/tests
./run-all.sh      # 전체
./913100.sh       # 탐지 룰만
```

현재 결과: `PASS=250  FAIL=0  SKIP=0`
- `913100` — 대표 UA 3종 + **`scanners-user-agents.data` 패턴 79개 전체**가 각각 403 차단 + 로그 확인, 정상 UA 2종 통과.
  (매 테스트마다 데이터 파일을 직접 읽어 패턴 전체를 스윕하므로 목록이 늘어도 자동 반영)
- 게이팅 룰(`913011`~`913018`)은 탐지 대상이 아니므로 테스트에서 제외한다(개념: [paranoia-gating.md](../../modsecurity/paranoia-gating.md)).

로그: `logs/local_test/REQUEST-913-SCANNER-DETECTION/` (`run-all.log`, `<rule-id>.log`,
`nginx-error.log`, `nginx-audit.log`)

---

## 6. 용어 미니 사전

| 용어 | 뜻 |
|------|-----|
| `@pmFromFile` | 파일의 패턴들과 부분 일치 검사 |
| `REQUEST_HEADERS:User-Agent` | 요청의 User-Agent 헤더 값 |
| `capture` | 매칭된 조각을 `TX.0` 등에 저장 |
| 어노말리 스코어 | 룰이 쌓는 위험 점수, 임계값 넘으면 `949110`이 차단 |
| paranoia level(PL) | 룰 민감도 단계(1~4) |
| `skipAfter` / `SecMarker` | 표식까지 건너뛰기 / 그 목적지 표식 |

---

## 7. 참고

- 스캐너 목록: `crs/rules/scanners-user-agents.data`
- 실행 모델: [../../modsecurity/execution-model.md](../../modsecurity/execution-model.md)
- 유사 파일: [REQUEST-911-METHOD-ENFORCEMENT](../REQUEST-911-METHOD-ENFORCEMENT/README.md)
- 관련: [REQUEST-901-INITIALIZATION](../REQUEST-901-INITIALIZATION/README.md)
