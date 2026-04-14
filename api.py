from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import TrustyCart

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.post("/api/scan")
async def scan_url(request: URLRequest):
    try:
        return TrustyCart.check_all_features(request.url)
    except Exception as e:
        return {"verdict": "Error", "score": 0, "positives": [], "negatives": [str(e)]}

@app.get("/")
async def root():
    return {"message": "TrustyCart API is Live!"}