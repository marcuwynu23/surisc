DIST_DIR := dist
ENTRY_POINT := cmd/surisc/main.go

NSIS_SCRIPT := installer/installer.nsis
NSIS_OUTPUT := $(DIST_DIR)/surisc-setup.exe

DEB_NAME := surisc
DEB_VERSION := 1.0.0

all: exe installer-nsis

exe:
	@echo "Building Windows executable..."
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 go build -o $(DIST_DIR)/surisc.exe $(ENTRY_POINT)

installer-nsis: exe
	@echo "Building NSIS installer..."
	makensis -DOUTPUT_FILE=$(NSIS_OUTPUT) $(NSIS_SCRIPT)

#----------------------------------
# Debian package
#----------------------------------
deb: exe check-fpm
	@echo "Building Debian (.deb) package..."
	fpm -s dir -t deb \
	  -n $(DEB_NAME) \
	  -v $(DEB_VERSION) \
	  --prefix /usr/local/bin \
	  $(DIST_DIR)/surisc.exe

check-fpm:
	@which fpm > /dev/null || (echo "fpm is not installed. Install it with: gem install --no-document fpm" && exit 1)

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(DIST_DIR)

.PHONY: all exe installer-nsis deb clean