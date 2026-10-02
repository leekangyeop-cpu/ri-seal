# 개인정보·데이터 — ri-seal 이 무엇을 기록하고 무엇을 내보내는가

[English](PRIVACY.en.md)

ri-seal 에는 서버가 없습니다. 사용 통계를 모으지 않고, 루트인사이드를 포함한 누구에게도 데이터를 보내지 않습니다.

## 1. 기기 밖으로 나가는 것
| 언제 | 무엇이 | 어디로 |
| --- | --- | --- |
| `ri-seal anchor` 를 **직접 실행할 때만** | 봉인의 지문(SHA-256) **32바이트** | OpenTimestamps 공개 캘린더 2곳(a.pool·b.pool.opentimestamps.org) |
| 〃 | 봉인 지문 32바이트 + **임의 난수 8바이트**(RFC 3161 요청 형식) | 시각 기관 1곳(기본 freetsa.org) |
| 〃(모든 인터넷 요청 공통) | 요청을 보내는 **IP 주소**, `User-Agent: ri-seal/<버전>`, TLS 접속 정보 | 위 서비스의 서버 기록에 남을 수 있음 |
| 그 밖의 모든 명령(`init`·`hook`·`claim-hook`·`seal`·`verify`·`status`·`ui`·`export`·`install`/`uninstall-claude-hook`) | **없음(0)** | — |

- 파일 이름·파일 내용·명령어·대화 내용·영수증은 `anchor` 로도 나가지 않습니다.
- `ri-seal ui` 는 이 컴퓨터의 127.0.0.1 에서만 열리고 외부 주소로 요청하지 않습니다(페이지 안에 외부 글꼴·스크립트·이미지 없음).
- `export` 는 파일을 만들 뿐 전송하지 않습니다. 그 파일을 누구에게 줄지는 사용자가 정합니다.
- 설치(`pip install … git+https://github.com/…`)는 ri-seal 이 아니라 pip 가 GitHub 에 접속하는 것입니다.

## 2. 이 컴퓨터에 남는 것
| 위치 | 내용 | 엄격(strict, 기본) | 일반(normal) |
| --- | --- | --- | --- |
| `.riseal/receipts.jsonl` | 도구 호출 한 번에 한 줄: 시각, 도구 이름, 파일 경로, 파일 지문, 명령어 HMAC, 세션 HMAC, 하위 에이전트 HMAC, 테스트 실행이면 `test` 표시와 통과·실패 **개수** | 모든 경로는 HMAC, 파일 지문도 HMAC | 민감하지 않은 프로젝트 안 경로와 SHA-256 은 그대로, 민감해 보이는 경로는 HMAC |
| `.riseal/claims.jsonl` | 주장 대조 한 문장에 한 줄: 종류, supported/unsupported/unknown, 근거 개수 | 문장은 **HMAC 만**, 파일은 개수만 | 문장 앞 200자와 그 안의 파일 이름(민감해 보이는 파일 이름이 있으면 HMAC) |
| `.riseal/seals.jsonl` · `proofs/` | 서명된 봉인, 시각 고정 영수증 | 봉인 대상 이름은 HMAC | 이름 그대로(민감해 보이는 파일은 자동 제외) |
| `.riseal/verify_log.jsonl` | `verify` 를 실행할 때마다 결과 개수(문제 수·변경 수) | 같음 | 같음 |
| `.riseal/hook_errors.log` | 훅이 실패한 시각과 오류 종류 이름 | 같음 | 같음 |
| `.riseal/config.json` · `pubkey.pem` | 키 ID, 공개키와 그 지문, 생성 시각, 기록 등급 | 같음 | 같음 |
| `~/.riseal/keys/<키ID>.pem` · `.pepper` | 서명 개인키와 HMAC 용 비밀값(권한 0600, 프로젝트 밖) | 같음 | 같음 |
| `.claude/settings.local.json`(또는 `--shared` 면 `settings.json`) | 설치한 훅 두 항목, 처음 원본은 `.bak` | 같음 | 같음 |

- **절대 기록하지 않는 것**: 파일 내용, 명령어 원문, 도구 출력 원문, 대화 원문, 비밀키 값.
- 테스트 실행의 통과·실패 개수는 출력의 마지막 요약 줄(`12 passed, 1 failed`)에서 숫자만 뽑아 둡니다.
- `claim-hook` 은 Claude Code 가 이미 이 컴퓨터에 남기는 대화 기록 파일(`transcript_path`)에서 **마지막 답변**만 읽습니다. 그 파일을 복사하거나 옮기지 않습니다.
- HMAC 은 프로젝트 밖의 비밀값(pepper)으로 만들기 때문에, pepper 가 없으면 원래 이름을 알아낼 수 없습니다. 짧은 이름이라도 추측으로 맞히기 어렵게 하려는 것입니다.

## 3. 엄격(strict)과 일반(normal)의 차이
- 0.2 부터 `ri-seal init` 의 기본값은 **strict** 입니다. 기록이나 `export` 묶음을 남에게 보여 줄 가능성이 있다면 그대로 두세요.
- `ri-seal init --privacy normal` 은 민감해 보이지 않는 경로를 읽을 수 있게 남깁니다. 혼자 쓰는 프로젝트에서 `status --details` 로 어떤 파일인지 바로 보고 싶을 때 씁니다.
- 0.1 로 만든 프로젝트는 설정이 그대로 유지됩니다(바뀌지 않음).

## 4. 지우는 방법
```bash
ri-seal uninstall-claude-hook          # 설치한 훅 두 항목만 제거(--shared 로 설치했다면 --shared). 미리보기는 --dry-run
rm -rf .riseal                          # 이 프로젝트의 영수증·봉인·주장 기록·증명 파일 삭제
rm ~/.riseal/keys/<키ID>.pem ~/.riseal/keys/<키ID>.pepper   # 키 삭제 — 되돌릴 수 없음
pip uninstall ri-seal
```
- 키를 지우면 새 봉인을 만들 수 없습니다. 이미 남에게 준 `export` 묶음은 그 안의 공개키로 계속 검증됩니다.
- pepper 를 지우면 strict 기록의 HMAC 이름을 다시 풀 수 없습니다(본인도).
- `anchor` 로 보낸 32바이트 지문은 공개 캘린더·비트코인 블록·시각 기관 기록에 남으며 지울 수 없습니다. 그 지문만으로 원래 기록을 알아낼 수는 없습니다.

문의: contact@rootinsidegroup.com
