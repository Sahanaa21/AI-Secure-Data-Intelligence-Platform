import os
import sys
from pathlib import Path

# Add the backend directory to path
sys.path.append(str(Path(__file__).parent))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi import Request
import time
import logging
from dotenv import load_dotenv

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ai_sdip")

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

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000
    
    # Don't log static file requests to keep logs clean
    if not request.url.path.startswith("/static") and not request.url.path.startswith("/app"):
        logger.info(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.2f}ms")
    
    return response

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
