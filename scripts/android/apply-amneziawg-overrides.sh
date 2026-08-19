#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIRECTORY/../.." && pwd)"
ANDROID_VENDOR_DIRECTORY="$REPOSITORY_ROOT/vendor/amneziawg-android"
ANDROID_PATCH_FILE="$REPOSITORY_ROOT/patches/amneziawg-android-network-telemetry.patch"
ANDROID_MEMORY_PATCH_FILE="$REPOSITORY_ROOT/patches/amneziawg-android-memory-diagnostics.patch"
GO_VENDOR_DIRECTORY="$REPOSITORY_ROOT/vendor/amneziawg-go"
GO_PATCH_FILE="$REPOSITORY_ROOT/patches/amneziawg-go-network-recovery.patch"
GO_MEMORY_PATCH_FILE="$REPOSITORY_ROOT/patches/amneziawg-go-android-memory.patch"
LOCK_DIRECTORY="$REPOSITORY_ROOT/.nelomai-locks"
LOCK_FILE="$LOCK_DIRECTORY/vendor-overrides.lock"
LOCK_WAIT_ATTEMPTS=300
lock_acquired=false
lock_mode=''
android_applied_by_this_run=false
go_applied_by_this_run=false
android_memory_applied_by_this_run=false
go_memory_applied_by_this_run=false

acquire_lock() {
  local attempt=0
  mkdir -p "$LOCK_DIRECTORY"
  if command -v flock >/dev/null 2>&1; then
    exec 9> "$LOCK_FILE"
    if ! flock -w 30 9; then
      printf 'Timed out waiting for vendor patch lock: %s\n' "$LOCK_FILE" >&2
      return 1
    fi
    lock_mode='flock'
    lock_acquired=true
    return
  fi
  if ! command -v shlock >/dev/null 2>&1; then
    printf 'No supported vendor patch lock utility is available\n' >&2
    return 1
  fi
  while ! shlock -f "$LOCK_FILE" -p "$$"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge "$LOCK_WAIT_ATTEMPTS" ]; then
      printf 'Timed out waiting for vendor patch lock: %s\n' "$LOCK_FILE" >&2
      return 1
    fi
    sleep 0.1
  done
  lock_mode='shlock'
  lock_acquired=true
}

release_lock() {
  if [ "$lock_acquired" != true ]; then
    return
  fi
  if [ "$lock_mode" = flock ]; then
    flock -u 9
    exec 9>&-
  elif [ "$lock_mode" = shlock ]; then
    local owner_pid=''
    if [ -f "$LOCK_FILE" ]; then
      IFS= read -r owner_pid < "$LOCK_FILE" || owner_pid=''
    fi
    if [ "$owner_pid" = "$$" ]; then
      rm -f "$LOCK_FILE"
    fi
  fi
  lock_acquired=false
  lock_mode=''
}

patch_state() {
  local vendor_directory="$1"
  local patch_file="$2"

  test -d "$vendor_directory/.git" || test -f "$vendor_directory/.git"
  test -f "$patch_file"

  if git -C "$vendor_directory" apply --reverse --check "$patch_file" >/dev/null 2>&1; then
    printf '%s\n' 'applied'
    return 0
  fi

  if git -C "$vendor_directory" apply --check "$patch_file" >/dev/null 2>&1; then
    printf '%s\n' 'pending'
    return 0
  fi

  printf 'Patch cannot be applied cleanly: %s\n' "$patch_file" >&2
  return 1
}

patch_is_applied() {
  local vendor_directory="$1"
  local patch_file="$2"

  test -d "$vendor_directory/.git" || test -f "$vendor_directory/.git"
  test -f "$patch_file"
  git -C "$vendor_directory" apply --reverse --check "$patch_file" >/dev/null 2>&1
}

rollback_partial_application() {
  local status=$?
  trap - EXIT
  set +e
  if [ "$status" -ne 0 ]; then
    if [ "$go_memory_applied_by_this_run" = true ]; then
      git -C "$GO_VENDOR_DIRECTORY" apply --reverse "$GO_MEMORY_PATCH_FILE"
    fi
    if [ "$android_memory_applied_by_this_run" = true ]; then
      git -C "$ANDROID_VENDOR_DIRECTORY" apply --reverse "$ANDROID_MEMORY_PATCH_FILE"
    fi
    if [ "$go_applied_by_this_run" = true ]; then
      git -C "$GO_VENDOR_DIRECTORY" apply --reverse "$GO_PATCH_FILE"
    fi
    if [ "$android_applied_by_this_run" = true ]; then
      git -C "$ANDROID_VENDOR_DIRECTORY" apply --reverse "$ANDROID_PATCH_FILE"
    fi
  fi
  release_lock
  exit "$status"
}

trap rollback_partial_application EXIT
acquire_lock

if ! patch_is_applied "$ANDROID_VENDOR_DIRECTORY" "$ANDROID_MEMORY_PATCH_FILE"; then
  android_patch_state="$(patch_state "$ANDROID_VENDOR_DIRECTORY" "$ANDROID_PATCH_FILE")"
  if [ "$android_patch_state" = pending ]; then
    git -C "$ANDROID_VENDOR_DIRECTORY" apply "$ANDROID_PATCH_FILE"
    android_applied_by_this_run=true
  fi
  android_memory_patch_state="$(patch_state "$ANDROID_VENDOR_DIRECTORY" "$ANDROID_MEMORY_PATCH_FILE")"
  if [ "$android_memory_patch_state" = pending ]; then
    git -C "$ANDROID_VENDOR_DIRECTORY" apply "$ANDROID_MEMORY_PATCH_FILE"
    android_memory_applied_by_this_run=true
  fi
fi

if ! patch_is_applied "$GO_VENDOR_DIRECTORY" "$GO_MEMORY_PATCH_FILE"; then
  go_patch_state="$(patch_state "$GO_VENDOR_DIRECTORY" "$GO_PATCH_FILE")"
  if [ "$go_patch_state" = pending ]; then
    git -C "$GO_VENDOR_DIRECTORY" apply "$GO_PATCH_FILE"
    go_applied_by_this_run=true
  fi
  go_memory_patch_state="$(patch_state "$GO_VENDOR_DIRECTORY" "$GO_MEMORY_PATCH_FILE")"
  if [ "$go_memory_patch_state" = pending ]; then
    git -C "$GO_VENDOR_DIRECTORY" apply "$GO_MEMORY_PATCH_FILE"
    go_memory_applied_by_this_run=true
  fi
fi
