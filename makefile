DIST_DIR := dist
ENTRY_POINT := cmd/surisc/main.go
WXS_FILE := installer/surisc.wxs
MSI_NAME := surisc.msi

all: exe msi

exe:
	@echo "Building Windows executable..."
	@mkdir -p $(DIST_DIR)
	go build -o $(DIST_DIR)/surisc.exe $(ENTRY_POINT)

installer-nsis: exe
	@echo "Building MSI installer..."
	@makensis installer/installer.nsis

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(DIST_DIR)