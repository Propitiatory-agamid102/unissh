#!/usr/bin/env bash
# Post-generation fixups for the Tauri iOS Xcode project (macOS only).
#
# `tauri ios init` regenerates client/src-tauri/gen/apple from cargo-mobile2's
# template, which ships two defaults that break the build on recent Xcode:
#
#   1. ENABLE_USER_SCRIPT_SANDBOXING = YES — the "Build Rust Code" run-script
#      phase then runs in Xcode's sandbox and is denied access to project.pbxproj,
#      failing with `Operation not permitted (os error 1)`. This is Xcode's script
#      sandbox, NOT a TCC/Full-Disk-Access issue (tccd logs nothing; the file is
#      readable outside the phase). Turning the sandbox off is the documented fix.
#   2. IPHONEOS_DEPLOYMENT_TARGET drifts to the build SDK instead of the value in
#      tauri.conf.json (bundle.iOS.minimumSystemVersion = 16.0), so an app built
#      with the latest SDK ends up installable only on the newest iOS.
#
# gen/apple is gitignored and regenerated, so re-run this after every `ios init`
# (the edits survive `ios build`/`ios dev`). `just ios-init` does both for you.
set -euo pipefail

# Locate project.pbxproj whether invoked from the repo root, client/, or src-tauri/.
pbx="client/src-tauri/gen/apple/unissh.xcodeproj/project.pbxproj"
[ -f "$pbx" ] || pbx="src-tauri/gen/apple/unissh.xcodeproj/project.pbxproj"
[ -f "$pbx" ] || pbx="gen/apple/unissh.xcodeproj/project.pbxproj"
if [ ! -f "$pbx" ]; then
  echo "error: project.pbxproj not found — run 'tauri ios init' first" >&2
  exit 1
fi

# 1) Force user-script sandboxing OFF in every build configuration. Idempotent:
#    drop any existing line first, then add exactly one NO per buildSettings block.
sed -i '' '/ENABLE_USER_SCRIPT_SANDBOXING = /d' "$pbx"
sed -i '' 's/buildSettings = {/buildSettings = {\
ENABLE_USER_SCRIPT_SANDBOXING = NO;/' "$pbx"

# 2) Pin the iOS deployment target to tauri.conf.json's minimum (16.0).
sed -i '' 's/IPHONEOS_DEPLOYMENT_TARGET = [0-9.]*;/IPHONEOS_DEPLOYMENT_TARGET = 16.0;/g' "$pbx"

# 3) Xcode "Run Script" phases get a minimal PATH that excludes Homebrew, so the
#    generated "Build Rust Code" phase (which runs `npm run -- tauri ios
#    xcode-script ...`) dies with `npm: command not found` in Xcode GUI builds —
#    even though npm works in the CLI. Prepend the common node/cargo locations to
#    the phase's PATH. Idempotent: only matches the un-patched `#!/bin/sh\nnpm`
#    form, so a second run is a no-op. (nvm-only setups: also symlink node/npm
#    into /usr/local/bin, which this PATH includes.)
sed -i '' 's|#!/bin/sh\\nnpm run|#!/bin/sh\\nexport PATH=/opt/homebrew/bin:/usr/local/bin:$HOME/.cargo/bin:$PATH\\nnpm run|' "$pbx"

n_no=$(grep -c 'ENABLE_USER_SCRIPT_SANDBOXING = NO;' "$pbx" || true)
n_path=$(grep -c 'export PATH=/opt/homebrew/bin' "$pbx" || true)
echo "✓ patched $pbx — sandboxing OFF ($n_no configs), target 16.0, build-phase PATH fixed ($n_path)"

# 4) Status bar style. The app ships viewport-fit=cover, so the WKWebView extends
#    behind the status bar/notch; that area shows the app's dark bg0, over which
#    iOS would otherwise draw DARK status-bar text (invisible). Request light
#    (white) content. The UI defaults to the dark theme; a static plist can't
#    follow a runtime light-mode switch (that needs native Swift in the view
#    controller — out of scope, and dark is the primary theme).
#    Info.plist is generated too, so patch it best-effort and NEVER fail the build.
plist=$(ls client/src-tauri/gen/apple/*_iOS/Info.plist \
           src-tauri/gen/apple/*_iOS/Info.plist \
           gen/apple/*_iOS/Info.plist 2>/dev/null | head -1 || true)
if [ -n "${plist:-}" ] && [ -f "$plist" ] && [ -x /usr/libexec/PlistBuddy ]; then
  pb=/usr/libexec/PlistBuddy
  "$pb" -c "Delete :UIViewControllerBasedStatusBarAppearance" "$plist" 2>/dev/null || true
  "$pb" -c "Add :UIViewControllerBasedStatusBarAppearance bool false" "$plist" 2>/dev/null || true
  "$pb" -c "Delete :UIStatusBarStyle" "$plist" 2>/dev/null || true
  "$pb" -c "Add :UIStatusBarStyle string UIStatusBarStyleLightContent" "$plist" 2>/dev/null || true
  echo "✓ patched $plist — light status-bar content"
else
  echo "• Info.plist not found (run after 'tauri ios init') — status-bar fixup skipped"
fi
