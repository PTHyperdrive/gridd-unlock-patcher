#!/bin/sh

if [ "$1" == "clean" ] || [ "$1" == "rebuild" ]; then
	rm -rf build gridd-unlock-patcher
fi

if [ -z "$1" ] || [ "$1" == "rebuild" ] || [ "$1" == "build" ]; then
	cmake -DCMAKE_BUILD_TYPE=Release -B build && make -j$(nproc) -C build && mv build/gridd-unlock-patcher .
fi
