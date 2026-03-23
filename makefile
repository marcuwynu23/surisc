DIST_DIR := dist
ENTRY_POINT := cmd/surisc/main.go
WXS_FILE := installer/surisc.wxs
MSI_NAME := surisc.msi
DEB_NAME := surisc
DEB_VERSION := 1.0.0

all: exe msi

exe:
	@echo "Building Windows executable..."
	@mkdir -p $(DIST_DIR)
	go build -o $(DIST_DIR)/surisc.exe $(ENTRY_POINT)

installer-nsis: exe
	@echo "Building MSI installer..."
	@makensis installer/installer.nsis

#----------------------------------
# Debian package target
# Requires fpm (install with: gem install --no-document fpm)
# Must run inside WSL/Linux environment
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

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(DIST_DIR)
