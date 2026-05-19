#!/usr/bin/env bash
# BoxPassword 로컬 릴리스 빌드 (코드사인 없이 개인용).
#
# Apple Developer 인증서가 없어도 .app 번들을 만들 수 있도록 ad-hoc 서명을 사용합니다.
# 결과물:
#   target/release/bundle/macos/BoxPassword.app
#   target/release/bundle/dmg/BoxPassword_<ver>_<arch>.dmg (선택)
#
# 다른 PC로 배포할 때는 Gatekeeper 격리 속성을 한 번 제거해야 합니다(아래 참고).

set -euo pipefail

bold() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
err()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; }

if [[ "$(uname -s)" != "Darwin" ]]; then
  err "이 스크립트는 macOS 전용입니다."
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bold "1/4  필수 도구 확인"
for cmd in cargo node npm; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    err "$cmd 가 PATH에 없습니다. ./scripts/setup-mac.sh 를 먼저 실행해 주세요."
    exit 1
  fi
done
if ! cargo tauri --version >/dev/null 2>&1; then
  err "cargo-tauri 가 설치되지 않았습니다. cargo install tauri-cli --version ^2"
  exit 1
fi
ok "cargo / node / cargo-tauri 모두 발견"

bold "2/4  품질 게이트"
warn "테스트(생략 시 BOXPASSWORD_SKIP_TESTS=1) — Argon2 기본 파라미터로 인해 ~10초 소요"
if [[ -z "${BOXPASSWORD_SKIP_TESTS:-}" ]]; then
  cargo test --workspace --no-fail-fast
  ok "cargo test 통과"
fi
cargo fmt --check
ok "rustfmt 정렬"

bold "3/4  릴리스 빌드"
# Tauri 2: codesign 비밀번호 미설정 → ad-hoc 서명. APPLE_SIGNING_IDENTITY 가 설정되어 있으면 그쪽을 따름.
if [[ -n "${APPLE_SIGNING_IDENTITY:-}" ]]; then
  ok "APPLE_SIGNING_IDENTITY 감지: $APPLE_SIGNING_IDENTITY"
  cd crates/bp-app
  cargo tauri build
else
  warn "Apple Developer ID 없이 진행합니다(ad-hoc 서명)."
  cd crates/bp-app
  cargo tauri build || true
  # 일부 환경에서 코드사인 실패해도 .app 자체는 생성됨. 명시적으로 ad-hoc 서명 다시 입힘.
  APP_PATH="$ROOT/target/release/bundle/macos/BoxPassword.app"
  if [[ -d "$APP_PATH" ]]; then
    codesign --force --deep --sign - "$APP_PATH"
    ok "ad-hoc 서명 완료"
  fi
fi
cd "$ROOT"

bold "4/4  결과물 안내"
APP_PATH="$ROOT/target/release/bundle/macos/BoxPassword.app"
DMG_DIR="$ROOT/target/release/bundle/dmg"

if [[ -d "$APP_PATH" ]]; then
  ok ".app: $APP_PATH"
fi
if [[ -d "$DMG_DIR" ]]; then
  for dmg in "$DMG_DIR"/*.dmg; do
    [[ -e "$dmg" ]] || continue
    ok ".dmg: $dmg"
  done
fi

cat <<EOF

다른 Mac으로 옮길 때는 한 번 Gatekeeper 격리 속성을 제거해 주세요.

  xattr -dr com.apple.quarantine /path/to/BoxPassword.app

정식 배포(우클릭→열기 없이 더블클릭 가능, 자동 업데이트, App Store)는
Apple Developer Program 가입 후 다음 환경 변수를 설정하고 다시 실행:

  export APPLE_SIGNING_IDENTITY="Developer ID Application: 이름 (TEAMID)"
  export APPLE_ID="apple-id@example.com"
  export APPLE_PASSWORD="앱별-비밀번호"
  export APPLE_TEAM_ID="TEAMID"
  ./scripts/build-release.sh

EOF
