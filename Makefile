check-code:
	cargo fmt --verbose --check --all -- --color always
	cargo clippy --all-features --all-targets --color always -- -D warnings

stable-output:
	@if [ -n "$$(git status --porcelain)" ]; then \
    	echo "Error: There are unstaged or uncommitted changes after running 'make check-code'."; \
    	exit 1; \
	else \
		echo "No unstaged or uncommitted changes found."; \
	fi

check: check-code stable-output

install-tools:
	cargo install --locked --path ln-simln-jamming --bin reputation-builder
	cargo install --locked --path ln-simln-jamming --bin forward-builder

install:
	cargo install --locked --path ln-simln-jamming
