# Changelog

## [unreleased] — v0.1.0-rc

### Core security
- Argon2id KDF + AES-256-GCM AEAD 봉인 포맷 `[ver:u8|alg:u8|nonce:12|ct|tag:16]`, AAD 에 항목 id+필드명 포함.
- `MasterKey`/`VaultKey` Zeroize ZeroizeOnDrop, `Debug` 는 `<redacted>` 만 노출.
- 마스터 비밀번호 변경 — vault_key 재봉인으로 옛 비번 무효화.

### Storage
- 단일 SQLite 파일(WAL) — `vault_meta / entries / entry_versions / groups / password_policies / otp_links / audit_log`.
- 멱등 ALTER + `pragma_table_info` 마이그레이션 (`favorite`, `group_id`, `notes_cipher`, `totp_seed_cipher`,
  `totp_algorithm`, `totp_period`, `totp_digits`, `rotation_days`).
- `.bpvault` 백업 포맷: `MAGIC("BPV1") | header_len | header_json | aead_body`, AAD 에 헤더 통째.
- 변경 이력 append-only, 임의 시점 롤백은 새 버전으로 기록.

### Password tooling
- `bp-passgen`: 정책 기반 무작위 + Diceware 스타일 패스프레이즈(256 단어 임베드).
- zxcvbn 3.x 강도 평가 래퍼 (`StrengthSummary`).
- 클립보드 복사 시 SHA-256 해시 기반 자동 클리어, 사용자가 다른 것 복사했으면 건드리지 않음.

### TOTP
- RFC 6238 HMAC-SHA1/SHA-256/SHA-512, 주기 1~3600초, 자릿수 6~10.
- `otpauth://` URL과 raw base32 시크릿 모두 파싱(범위 밖 파라미터는 기본값으로 fallback).
- 항목별 시드 봉인(`AAD = box-password/entry/totp/v1:<id>`), config 는 plain 컬럼.
- UI 는 1초마다 코드/도넛 갱신, 클릭 복사.

### Import / Export
- `.bpvault` 내보내기/복구 — 다이얼로그 통합, 기존 파일은 `vault.db.bak` 보존.
- **CSV 가져오기** — 1Password / Bitwarden / Chrome 등에서 export 한 CSV 직접 붙여넣기.
  헤더에서 name/title, username, password, url, notes, folder, totp 자동 인식.
  folder 열의 값은 그룹으로 자동 생성.

### Desktop integration
- Tauri 2.x 메인 윈도우 + Quick Search 보조 윈도우.
- 메뉴바 트레이 — 잠금/해제 상태 배지, 즐겨찾기/최근 서브메뉴(클릭 즉시 복사), 즉시 비밀번호 생성, 잠그기/클립보드 비우기/종료.
- 글로벌 단축키 ⌘⇧K → Quick Search 팝오버 — Enter 로 클립보드 복사, ↑↓ 이동, Esc 닫기.
- `arboard` 클립보드 — 30초 SHA-256 해시 비교 자동 클리어.
- **자동 입력(키스트로크) 기능 v0.1 에서 제거** — 모든 패스워드 전달은 클립보드 경유.
- 메인 창 close 버튼 → 종료 대신 hide.

### Auto-lock / Notifications / Rotation
- 자동 잠금: 활동 타이머(1/5/15/30/60분), 창 blur 시 즉시 잠금 옵션, **시스템 슬립 감지 후 자동 잠금**.
- `tauri-plugin-notification` 시스템 알림 — 자동 잠금, 슬립 잠금, 클립보드 클리어, 변경 주기 도래.
- **비밀번호 변경 주기**: 항목별 `rotation_days` (30~365, 사용 안 함).
  - 잠금 해제 직후 1회 자동 검사 → overdue / upcoming 카운트 토스트 + 알림.
  - 상세 헤더에 ⏰/⚠/🗓 pill, 클릭 시 즉시 수정.

### Health / Discovery
- 사이드바 그룹 — 8색 팔레트, 인라인 이름 편집/색상 순환/삭제.
- 건강 검진 대시보드 — 평균 강도, 약한/중복/노후 비밀번호 카운트 + 항목별 점프.
- 항목 필터: 전체 / 즐겨찾기 / 최근 / 그룹별. 정렬: 제목순 / 최근 수정 / 즐겨찾기 우선.

### UX / Branding
- 빨강 톤 팔레트 (다크/라이트) + 황금 액센트(TOTP/카운트다운/클립보드 도넛).
- 강철 vault 문 + 황금 콤비네이션 다이얼 + 코너 볼트 아이콘 (32/128/256/512/1024 + 트레이 변형).
- UI 내부 공통 SVG 심볼(`#boxpassword-mark`) — 상단바·셋업·잠금 화면 일관.
- 모달 fade+scale 진입, 토스트 slide-up, 빈 상태 자물쇠 일러스트 + 단축키 힌트.

### Tests / Docs
- `bp-crypto`: KDF/AEAD/TOTP RFC 6238 벡터(SHA-1/256/512) 포함.
- `bp-storage`: 초기화 → CRUD → 즐겨찾기 → 메모 → TOTP → 마스터 변경 → 그룹 → 백업/복구 라운드트립.
- `docs/FEATURES.md`, `docs/SETUP_MAC.md`, `docs/TEST_CHECKLIST.md`.

---

다음 후보(v0.2~):
- 코드사인 + 공증 + 자동 업데이트(`tauri-plugin-updater`)
- 멀티 vault / 빠른 전환
- macOS NSWorkspace 정식 슬립 감지
- 첨부 파일(라이선스 키 PDF, 복구 코드 이미지)
- 브라우저 확장 연동
- BoxOTP 외부 연동 구체 구현
- 항목 카운터 기반 HOTP 지원
