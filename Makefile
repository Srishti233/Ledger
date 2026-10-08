.PHONY: install test lint cov contracts-deps contracts-test up down reset demo eval clean

install:
	pip install -e ".[dev,postgres]"

lint:
	ruff check .

test:
	pytest -m "not integration"

# Needs `anvil` running and `make contracts-build` done.
test-integration:
	pytest -m integration

cov:
	pytest --cov=ledger --cov-report=term-missing --cov-fail-under=80

contracts-deps:
	cd contracts && forge install --no-git foundry-rs/forge-std

contracts-build:
	cd contracts && forge build

contracts-test: contracts-deps
	cd contracts && forge test -vv && forge coverage --report summary

up:
	docker compose up --build -d

down:
	docker compose down

# Wipes the chain AND Ledger's index (they must be reset together).
reset:
	docker compose down -v

demo:
	bash scripts/demo.sh

# Real gas/timing numbers from the running local chain, copied into ./results
eval:
	docker compose exec -T ledger ledger eval --sizes 1,10,100,1000 --out /tmp/results
	mkdir -p results
	docker compose cp ledger:/tmp/results/. results/

clean:
	rm -rf data .pytest_cache .coverage htmlcov contracts/out contracts/cache
