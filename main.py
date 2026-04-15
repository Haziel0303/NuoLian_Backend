import os

from fastapi import FastAPI, HTTPException

from app.routes import database, plugin, tally, wecom


def _env_enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

app.include_router(wecom.router)

if _env_enabled("ENABLE_TALLY_ROUTES"):
    app.include_router(tally.router)
if _env_enabled("ENABLE_DATABASE_ROUTES"):
    app.include_router(database.router)
if _env_enabled("ENABLE_PLUGIN_ROUTES"):
    app.include_router(plugin.router)


@app.get("/")
async def root():
    raise HTTPException(status_code=404, detail="Not Found")
