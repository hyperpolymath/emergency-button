# SPDX-License-Identifier: AGPL-3.0-or-later
# Emergency Button - Build System

.PHONY: all build run clean test help

# Default target
all: build

# Build the V application
build:
	v -o emergency-button src/

# Build with optimizations
release:
	v -prod -o emergency-button src/

# Run directly
run:
	v run src/ trigger

# Run with dry-run flag
dry-run:
	v run src/ trigger --dry-run

# Clean build artifacts
clean:
	rm -f emergency-button
	rm -rf incident-*/

# Format code
fmt:
	v fmt -w src/

# Check code without building
check:
	v -check src/

# Install to ~/.local/bin
install: release
	mkdir -p ~/.local/bin
	cp emergency-button ~/.local/bin/
	@echo "Installed to ~/.local/bin/emergency-button"

# Uninstall
uninstall:
	rm -f ~/.local/bin/emergency-button

help:
	@echo "Emergency Button - Build Targets"
	@echo ""
	@echo "  make build    - Build the application"
	@echo "  make release  - Build with optimizations"
	@echo "  make run      - Run directly (v run)"
	@echo "  make dry-run  - Run with --dry-run flag"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make fmt      - Format source code"
	@echo "  make check    - Check code without building"
	@echo "  make install  - Install to ~/.local/bin"
	@echo "  make help     - Show this help"
