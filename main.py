from fastapi import FastAPI
from app.routes import tally

app = FastAPI()

app.include_router(tally.router)

@app.get("/")
async def root():
    return {"message": "server is working"}
