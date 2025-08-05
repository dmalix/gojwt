default:
	@echo "Makefile: Please specify a target to make."
	@echo "------------------------------------------"
	@grep '^[a-zA-Z0-9_-]*:' Makefile | grep -v '^default:'

check:
	go fmt ./...
	go vet ./...
	go test ./...

