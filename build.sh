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

# Target Java 17 bytecode. 17 is the baseline this project is written and tested against, so the
# jar runs unchanged on JDK 17 and anything newer (your OpenJDK 26 included). Override if you
# ever need a different floor:  SILVERDETECTOR_RELEASE=21 ./build.sh
release=${SILVERDETECTOR_RELEASE:-17}
javac_version=$(javac -version 2>&1 | grep -i '^javac' | awk '{print $2}')
echo "compiling for Java $release (using javac ${javac_version:-unknown})"

find src -name '*.java' > build/sources.txt
javac --release "$release" -Xlint:all -d build @build/sources.txt

# The .tsv knowledge base rides along inside the jar as a fallback; the copies in data/
# still win when they are present, which is what makes editing them work without a rebuild.
mkdir -p build/data
cp data/*.tsv build/data/

jar --create --file silverdetector.jar --main-class silverdetector.Main -C build . >/dev/null

echo "built silverdetector.jar"
echo "run it with:  ./bin/silverdetector --help"
