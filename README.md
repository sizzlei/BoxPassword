# BoxPassword

> 개인용 패스워드 관리 데스크톱 앱 · Rust + Tauri 2.x · macOS / Windows

마스터 비밀번호 외에는 어떤 비밀도 평문으로 보관하지 않는, 변경 이력·백업·복구·TOTP까지
1급 시민으로 다루는 로컬 우선(local-first) 패스워드 매니저입니다.

- 처음 사용자 → [`docs/USER_GUIDE.md`](./docs/USER_GUIDE.md) (단계별 가이드 + 스크린샷)
- 기능 레퍼런스 → [`docs/FEATURES.md`](./docs/FEATURES.md)
- 초기 설계 → [`BoxPassword_Design.docx`](./BoxPassword_Design.docx)

---

## 핵심 기능 한눈에

**보안 기반**
- Argon2id로 마스터 키 도출 → AES-256-GCM(96-bit nonce, 128-bit tag)으로 vault 봉인
- AAD에 항목 id + 필드명을 포함해 봉인 슬롯 교차 공격 차단
- VaultKey / MasterKey 모두 `zeroize` ZeroizeOnDrop. 입력 비밀번호도 사용 즉시 zeroize
- 클립보드: SHA-256 해시 비교 기반 자동 클리어. 평문은 메모리에 ~ms 단위로만 머무름
- 자동 잠금: 비활동 N분 후 / 창 포커스 잃을 때 옵션 / 트레이 메뉴 / ⌘L 단축키
- 마스터 비밀번호 변경 — vault_key 재봉인으로 옛 비번 무효화

**일상 사용**
- 항목 추가/검색/삭제/즐겨찾기/그룹(컬러 코드)
- 비밀번호 변경 시 자동 버전 이력. 임의 시점 롤백
- 메모 필드(봉인 저장)
- TOTP 2단계 인증 — otpauth URL 또는 base32 시크릿 가져오기, 30초 도넛으로 라이브 표시
- 패스워드 생성기 — 정책 기반 무작위 + Diceware 스타일 패스프레이즈 + 라이브 zxcvbn 강도

**입력/접근**
- 메뉴바 트레이 아이콘 + 잠금/해제 상태 배지
- 트레이에서 즐겨찾기/최근 항목 클릭 즉시 클립보드 복사
- 트레이에서 즉시 비밀번호 생성 (랜덤/패스프레이즈)
- ⌘⇧K Quick Search 팝오버 — 어디서든 검색 → Enter 클립보드 복사
- 모든 패스워드 전달은 클립보드 경유 (자동 입력/키스트로크 미사용)

**관리**
- 백업/복구 — `.bpvault` 단일 봉인 파일(MAGIC + JSON 헤더 + AEAD body)
- 다른 매니저(1Password / Bitwarden / Chrome 등) CSV 가져오기, folder 열 → 그룹 자동 생성
- 건강 검진 대시보드 — 약한/중복/오래된 비밀번호 자동 감지
- 비밀번호 변경 주기 + 잠금 해제 시 알림
- 시스템 슬립/포커스 잃음/비활동 N분 후 자동 잠금
- 라이트/다크 테마 + 시스템 추종

---

## 빠른 시작

### macOS

```bash
./scripts/setup-mac.sh                    # 환경 설치 (Xcode CLT, Homebrew, rustup, Node, Tauri CLI)
cd crates/bp-app && cargo tauri dev       # 개발 모드
./scripts/build-release.sh                # 로컬 릴리스 빌드 → target/release/bundle/{macos,dmg}/
```

자세한 셋업은 [`docs/SETUP_MAC.md`](./docs/SETUP_MAC.md).

### Windows

```powershell
# 환경 설치는 docs/SETUP_WIN.md 따라가기 (Build Tools, WebView2, rustup, Node, Tauri CLI)
cd crates\bp-app; cargo tauri dev          # 개발 모드
.\scripts\build-release.ps1                # 로컬 릴리스 빌드 → target\release\bundle\{msi,nsis}\
```

자세한 셋업은 [`docs/SETUP_WIN.md`](./docs/SETUP_WIN.md).

### CI (GitHub Actions)

`.github/workflows/build.yml` 이 PR / 푸시 시 lint + test 를, 태그 `v*` 푸시 또는 수동 실행 시
macOS(Apple Silicon + Intel) + Windows x64 산출물을 자동 빌드하고 Release 에 첨부합니다.

## 디렉터리 구조

```
BoxPassword/
├─ Cargo.toml                 # 워크스페이스
├─ rust-toolchain.toml        # stable 채널 고정
├─ docs/
│  ├─ SETUP_MAC.md            # 셋업 가이드
│  └─ FEATURES.md             # 사용자용 기능 안내
├─ scripts/
│  ├─ setup-mac.sh            # 개발 환경 자동 설치
│  └─ build-release.sh        # 로컬 릴리스 빌드
├─ crates/
│  ├─ bp-core/                # 도메인 (Entry, Group, PasswordPolicy, EntryVersion)
│  ├─ bp-crypto/              # Argon2id, AES-GCM, TOTP(HMAC-SHA1), Zeroize 래퍼
│  ├─ bp-passgen/             # 랜덤/패스프레이즈 생성 + zxcvbn
│  ├─ bp-storage/             # rusqlite Vault — 스키마, 봉인 CRUD, 백업, 마스터 변경
│  ├─ bp-otp/                 # OtpProvider 트레잇 (외부 OTP 연동 자리)
│  └─ bp-app/                 # Tauri 호스트 + 트레이 + Quick Search
├─ ui/
│  ├─ index.html              # 메인 윈도우
│  └─ quick.html              # 글로벌 단축키 팝오버
└─ BoxPassword_Design.docx    # 설계 문서
```

## 단축키

| 단축키 | 동작 |
|---|---|
| ⌘⇧K | Quick Search 팝오버 (어디서든) |
| ⌘N | 메인 창에서 새 항목 |
| ⌘F | 검색 박스 포커스 |
| ⌘L | Vault 잠그기 |
| Esc | 모달/팝오버 닫기 |

## 마일스톤

| ID | 산출물 | 상태 |
|---|---|---|
| M0 | Cargo 워크스페이스 + Tauri 셸 | ✅ |
| M1 | Argon2id + AES-GCM 봉인, 파일 vault, 잠금/해제, 항목 CRUD | ✅ |
| M2 | 검색/정렬, 자동 잠금, 클립보드 zeroize, 즐겨찾기 | ✅ |
| M3 | 변경 이력 UI + 롤백 + 자동 입력 (enigo) | ✅ |
| M4 | 패스워드 생성기 / zxcvbn 강도 | ✅ |
| M5 | `.bpvault` 백업 / 복구 | ✅ |
| M6 | TOTP 자체 구현 (BoxOTP 스펙 도착 시 외부 연동) | ✅ |
| ★  | 그룹, 건강 검진, 트레이, Quick Search, 마스터 변경, 메모 | ✅ |
| M7 | 코드사인 + 자동 업데이트 (Apple Developer 계정 필요) | ⏳ |

## 테스트

```bash
cargo test --workspace        # 모든 단위/통합 테스트
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

주요 테스트:
- `bp-crypto`: KDF 결정성, AEAD 라운드트립/변조/오답 키, TOTP RFC 6238 벡터
- `bp-storage`: 초기화 → 잠금 해제 → 항목 CRUD → 버전 → 즐겨찾기 → 노트/TOTP → 마스터 변경 → 백업 라운드트립

## 보안 가정

- 마스터 비밀번호는 충분한 강도여야 한다(zxcvbn 3+ 권장)
- macOS 키체인이나 OS 보안 저장소를 사용하지 않는다 — vault 파일은 사용자의 책임
- 시스템 메모리/스왑은 신뢰한다 — 디스크 암호화(FileVault) 필수
- 자동 입력은 손쉬운 사용 권한이 켜진 상태를 가정

## 라이선스

MIT — [`LICENSE`](./LICENSE) 참고.
