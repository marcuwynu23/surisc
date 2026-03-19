DIST_DIR := dist
ENTRY_POINT := cmd/surisc/main.go
all:
	go build -o $(DIST_DIR)/surisc.exe $(ENTRY_POINT)

test:
	go test ./...



.PHONY: clean
clean:
	rm -rf $(DIST_DIR)