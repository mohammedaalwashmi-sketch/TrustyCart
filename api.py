from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import TrustyCart

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # التعديل الأول: False لحل مشكلة الحظر من متصفح كروم
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.post("/api/scan")
def scan_url(request: URLRequest):  # التعديل الثاني: حذفنا async لمنع تعليق السيرفر (Blocking)
    try:
        return TrustyCart.check_all_features(request.url)
    except Exception as e:
        return {"verdict": "Error", "score": 0, "positives": [], "negatives": [str(e)]}

@app.get("/")
def root():
    return {"message": "TrustyCart API is Live!"}
