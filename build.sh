#!/bin/sh
# Build silverdetector.jar. Needs nothing but a JDK - no Maven, no Gradle, no network.
#
#   ./build.sh            compile into build/ and package silverdetector.jar
#   ./build.sh clean      remove build output
#
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

if [ "${1:-}" = "clean" ]; then
    rm -rf build silverdetector.jar
    echo "cleaned"
    exit 0
fi

if ! command -v javac >/dev/null 2>&1; then
    echo "build.sh: javac not found - install a JDK (pacman -S jdk-openjdk)" >&2
    exit 1
fi

rm -rf build
mkdir -p build

# --release 17 so the jar also runs on older JDKs than the one that built it.
find src -name '*.java' > build/sources.txt
javac --release 17 -Xlint:all -d build @build/sources.txt

# The .tsv knowledge base rides along inside the jar as a fallback; the copies in data/
# still win when they are present, which is what makes editing them work without a rebuild.
mkdir -p build/data
cp data/*.tsv build/data/

jar --create --file silverdetector.jar --main-class silverdetector.Main -C build . >/dev/null

echo "built silverdetector.jar"
echo "run it with:  ./bin/silverdetector --help"
