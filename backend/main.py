import os
import sys
from pathlib import Path

# Add the backend directory to path
sys.path.append(str(Path(__file__).parent))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv

load_dotenv()

from routers import analyze

app = FastAPI(
    title="AI Secure Data Intelligence Platform",
    description="AI Gateway + Scanner + Log Analyzer + Risk Engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router)

# Serve frontend static files — mount at root path for correct relative URLs
frontend_path = Path(__file__).parent.parent / "frontend"
if frontend_path.exists():
    # Mount frontend directory so style.css and app.js resolve correctly
    app.mount("/app", StaticFiles(directory=str(frontend_path), html=True), name="frontend")
    # Also keep /static for direct access
    app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")

    @app.get("/")
    async def serve_frontend():
        return FileResponse(str(frontend_path / "index.html"))

    @app.get("/favicon.ico")
    async def favicon():
        return FileResponse(str(frontend_path / "index.html"))

@app.get("/health")
async def health():
    return {"status": "ok", "service": "AI Secure Data Intelligence Platform"}
