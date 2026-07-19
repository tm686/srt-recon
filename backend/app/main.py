from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db.engine import init_db, async_session
from app.services.settings_service import seed_defaults
from app.routers import health, settings as settings_router, projects, api_keys, scans, results, export


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    async with async_session() as db:
        await seed_defaults(db)
    app.state.fernet_key = None
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


OPEN_PATHS = {
    "/api/health",
    "/api/setup/status",
    "/api/setup/master-password",
    "/api/auth/unlock",
    "/api/auth/lock",
    "/docs",
    "/openapi.json",
}


@app.middleware("http")
async def auth_gate(request: Request, call_next):
    path = request.url.path

    if path in OPEN_PATHS or not path.startswith("/api/"):
        return await call_next(request)

    # Check setup
    if not hasattr(request.app.state, "fernet_key"):
        return Response(status_code=500, content="Server not initialized")

    # Vault-gated paths
    if "/keys" in path:
        if request.app.state.fernet_key is None:
            return Response(
                status_code=423,
                content='{"detail":"Vault is locked"}',
                media_type="application/json",
            )

    return await call_next(request)


app.include_router(health.router)
app.include_router(settings_router.router)
app.include_router(projects.router)
app.include_router(api_keys.router)
app.include_router(scans.router)
app.include_router(results.router)
app.include_router(export.router)
