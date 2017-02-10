
.PHONY: all
all: build.ninja
	@ninja

build.ninja: $(MAKEFILE_LIST) configure
	@./configure > $@

.PHONY: clean
clean: build.ninja
	@ninja -t clean
	rm -f build.ninja
