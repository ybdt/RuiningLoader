all: clean
	@echo "  GO  dist/stealthpalace.so"
	@mkdir -p dist
	@cp config.yaml ax_config.axs ./dist/
	@go mod tidy -e 2>/dev/null || true
	@GOEXPERIMENT=jsonv2,greenteagc go build -buildmode=plugin -ldflags="-s -w" -o ./dist/stealthpalace.so .

clean:
	@rm -rf dist
