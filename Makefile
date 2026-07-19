# SRT-Recon Makefile
# Quick commands for install, run, and maintenance

.PHONY: install run stop clean reset build deploy-prep help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Full installation (deps + tools + config)
	@./install.sh

run: ## Start backend + frontend dev servers
	@./run.sh

backend: ## Start backend only
	@cd backend && uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

frontend: ## Start frontend only
	@cd frontend && npm run dev

build: ## Production build of frontend
	@cd frontend && npm run build

clean: ## Remove generated files (node_modules, .venv, dist, db)
	rm -rf frontend/node_modules frontend/dist
	rm -rf backend/.venv
	rm -f backend/srt_recon.db

reset: ## Reset database (delete and recreate on next start)
	rm -f backend/srt_recon.db
	@echo "[+] Database reset. Will be recreated on next start."

typecheck: ## Run TypeScript type checking
	@cd frontend && npx tsc --noEmit

lint: ## Lint frontend code
	@cd frontend && npx oxlint .

deploy-prep: ## Prepare for deployment (build + package)
	@echo "[*] Building frontend..."
	@cd frontend && npm run build
	@echo "[*] Creating deployment archive..."
	@tar --exclude='node_modules' \
	     --exclude='.venv' \
	     --exclude='frontend/dist' \
	     --exclude='.git' \
	     --exclude='*.db' \
	     -czf srt-recon-deploy.tar.gz \
	     -C "$(shell dirname $(PWD))" \
	     "$(shell basename $(PWD))"
	@echo "[+] Archive: srt-recon-deploy.tar.gz"
	@echo "    Transfer to LP+ and run: tar xzf srt-recon-deploy.tar.gz && cd srt-recon && ./install.sh"

transfer: ## Create transfer bundle (excludes heavy deps)
	@tar --exclude='node_modules' \
	     --exclude='.venv' \
	     --exclude='.git' \
	     --exclude='*.db' \
	     --exclude='uv.lock' \
	     -czf /tmp/srt-recon-transfer.tar.gz \
	     -C "$(shell dirname $(realpath .))" \
	     "$(shell basename $(realpath .))"
	@ls -lh /tmp/srt-recon-transfer.tar.gz
	@echo "[+] Transfer bundle: /tmp/srt-recon-transfer.tar.gz"
	@echo "    scp /tmp/srt-recon-transfer.tar.gz user@lp-host:~/"
	@echo "    Then on LP+: tar xzf srt-recon-transfer.tar.gz && cd srt-recon && ./install.sh"
