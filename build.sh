#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
mkdir -p build/classes build/tests dist
find src -name '*.java' > build/sources.txt
find test -name '*.java' > build/tests.txt
javac --release 17 -encoding UTF-8 -d build/classes @build/sources.txt
javac --release 17 -encoding UTF-8 -cp build/classes -d build/tests @build/tests.txt
java -cp build/classes:build/tests portfolio.hostbaseline.Tests
jar --create --file dist/hostbaseline.jar --main-class portfolio.hostbaseline.Main -C build/classes .
