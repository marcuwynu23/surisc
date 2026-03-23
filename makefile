DIST_DIR := dist
ENTRY_POINT := cmd/surisc/main.go

NSIS_SCRIPT := installer/installer.nsis
NSIS_OUTPUT := $(DIST_DIR)/surisc-setup.exe
NSIS_VERSION := 1.0.0

DEB_NAME := surisc
DEB_VERSION ?= 1.0.0

all: exe installer-nsis

# ----------------------------
# Windows binary
# ----------------------------
exe:
	@echo "Building Windows executable..."
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 go build -o $(DIST_DIR)/surisc.exe $(ENTRY_POINT)

# ----------------------------
# Linux binary (REQUIRED for .deb)
# ----------------------------
linux:
	@echo "Building Linux binary..."
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(DIST_DIR)/surisc $(ENTRY_POINT)

# ----------------------------
# NSIS Installer
# ----------------------------
installer-nsis: exe
	@echo "Building NSIS installer..."
	@makensis \
	  -DOUTPUT_FILE=$(NSIS_OUTPUT) \
	  -DPRODUCT_VERSION=$(VERSION) \
	  $(NSIS_SCRIPT)

# ----------------------------
# Debian package
# ----------------------------
deb: linux check-fpm
	@echo "Building Debian (.deb) package..."
	fpm -s dir -t deb \
	  -n $(DEB_NAME) \
	  -v $(DEB_VERSION) \
	  --description "Surisc CLI tool" \
	  --prefix /usr/local/bin \
	  $(DIST_DIR)/surisc

# ----------------------------
# Test
# ----------------------------
test:
	@echo "Running tests..."
	go test ./...

# ----------------------------
# FPM check
# ----------------------------
check-fpm:
	@which fpm > /dev/null || (echo "fpm is not installed. Install it with: gem install --no-document fpm" && exit 1)

# ----------------------------
# Clean
# ----------------------------
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(DIST_DIR)

.PHONY: all exe linux installer-nsis deb test clean