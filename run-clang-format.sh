#!/usr/bin/env bash
set -euo pipefail

if (( $# == 0 )); then
  echo "Usage: $0 <dir> [dir2 ...]"
  exit 2
fi

# Adjust file patterns as needed
name_args=(
  -name '*.c'  -o -name '*.cc'  -o -name '*.cpp' -o -name '*.cxx'
  -o -name '*.h' -o -name '*.hh' -o -name '*.hpp' -o -name '*.hxx'
  -o -name '*.ipp' -o -name '*.tpp' -o -name '*.inl'
)

# Common dirs to skip while recursing (tweak/remove as you like)
prune_args=(
  -name .git -o -name build -o -name bazel-* -o -name cmake-build-* -o -name .cache
)

for dir in "$@"; do
  [[ -d "$dir" ]] || { echo "Not a directory: $dir" >&2; exit 1; }

  find "$dir" \
    -type d \( "${prune_args[@]}" \) -prune -o \
    -type f \( "${name_args[@]}" \) -print0 \
  | xargs -0 clang-format -i
done
