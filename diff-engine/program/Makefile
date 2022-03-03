arm-gcc := arm-linux-musleabi-gcc
aarch64-gcc := aarch64-linux-musl-gcc

.PHONY: build
build:
	$(arm-gcc) -static -march=armv7-a -O0 template.c -o template_arm
	$(arm-gcc) -static -mthumb -march=armv7-a -O0 template.c -o template_thumb
	$(aarch64-gcc) -static -march=armv8-a -O0 template.c -o template_arm64
