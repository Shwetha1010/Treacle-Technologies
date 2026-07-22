from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.api import auth, chat

app = FastAPI(
    title="Agentic SOC Assistant",
    description="An AI-powered agentic assistant for Security Operations Center (SOC) analysts to query deception logs and binaries analytics.",
    version="1.0.0"
)

# Enable CORS for local testing/development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API v1 Router Registration
app.include_router(auth.router, prefix="/api/v1")
app.include_router(chat.router, prefix="/api/v1")

@app.get("/api/v1/health", tags=["health"])
def health_check():
    return {"status": "healthy"}

# Mount static folder for CSS, JS and asset resources
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Catch-all routes to serve Single Page Application
@app.get("/")
def home():
    return FileResponse("app/static/index.html")

@app.get("/login")
def login_page():
    return FileResponse("app/static/index.html")

@app.get("/dashboard")
def dashboard_page():
    return FileResponse("app/static/index.html")
