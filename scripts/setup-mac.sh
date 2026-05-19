#!/usr/bin/env bash
# BoxPassword — macOS 개발 환경 자동 설정 스크립트.
# 멱등하게 동작합니다. 이미 설치된 도구는 건너뜁니다.

set -euo pipefail

# ---------- ui helpers ----------
bold() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
err()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; }

require_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    err "이 스크립트는 macOS 전용입니다. (현재: $(uname -s))"
    exit 1
  fi
}

# ---------- steps ----------

step_xcode_clt() {
  bold "1/6  Xcode Command Line Tools"
  if xcode-select -p >/dev/null 2>&1; then
    ok "이미 설치됨: $(xcode-select -p)"
    return
  fi
  warn "설치를 시작합니다. GUI 다이얼로그가 뜨면 'Install'을 눌러주세요."
  xcode-select --install || true
  # 사용자가 GUI 설치를 끝낼 때까지 폴링.
  local waited=0
  while ! xcode-select -p >/dev/null 2>&1; do
    sleep 5
    waited=$((waited + 5))
    if (( waited % 30 == 0 )); then
      warn "여전히 설치 대기 중 (${waited}s)…"
    fi
  done
  ok "설치 완료: $(xcode-select -p)"
}

step_homebrew() {
  bold "2/6  Homebrew"
  if command -v brew >/dev/null 2>&1; then
    ok "$(brew --version | head -1)"
    return
  fi
  warn "Homebrew를 설치합니다."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  if [[ -x /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
    # zsh 사용자 기본 경로 등록(중복 등록은 피함)
    if [[ -n "${ZDOTDIR:-$HOME}" && -f "$HOME/.zprofile" ]]; then
      grep -q 'brew shellenv' "$HOME/.zprofile" || \
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> "$HOME/.zprofile"
    fi
  elif [[ -x /usr/local/bin/brew ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
  ok "설치 완료: $(brew --version | head -1)"
}

step_rustup() {
  bold "3/6  Rust (rustup)"
  if ! command -v rustup >/dev/null 2>&1; then
    warn "rustup을 설치합니다."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain stable --profile default
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
  rustup default stable >/dev/null
  rustup component add rustfmt clippy >/dev/null 2>&1 || true
  ok "rustc:  $(rustc --version)"
  ok "cargo:  $(cargo --version)"
}

step_node() {
  bold "4/6  Node.js (≥ 20)"
  local need_install=1
  if command -v node >/dev/null 2>&1; then
    local major
    major=$(node -p "process.versions.node.split('.')[0]")
    if (( major >= 20 )); then
      ok "node $(node -v)"
      return
    fi
    warn "현재 node $(node -v) 가 20 미만입니다. brew로 업그레이드합니다."
  else
    warn "Node.js가 없습니다. brew로 설치합니다."
  fi
  brew install node
  ok "node $(node -v)"
  ok "npm  $(npm -v)"
}

step_tauri_cli() {
  bold "5/6  Tauri CLI (v2)"
  if cargo tauri --version >/dev/null 2>&1; then
    ok "$(cargo tauri --version)"
    return
  fi
  warn "tauri-cli를 설치합니다(수 분 소요될 수 있습니다)."
  cargo install tauri-cli --version "^2" --locked
  ok "$(cargo tauri --version)"
}

step_workspace_check() {
  bold "6/6  워크스페이스 컴파일 점검"
  local root
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  pushd "$root" >/dev/null
  cargo check --workspace
  popd >/dev/null
  ok "cargo check --workspace 통과"
}

main() {
  require_macos
  step_xcode_clt
  step_homebrew
  step_rustup
  step_node
  step_tauri_cli
  step_workspace_check

  bold "🎉 셋업 완료"
  cat <<'EOF'

다음 명령으로 개발 셸을 띄울 수 있습니다.

    cd crates/bp-app
    cargo tauri dev

윈도우가 떠 "pong from BoxPassword core" 가 표시되면 정상입니다.

EOF
}

main "$@"
