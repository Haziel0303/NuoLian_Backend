from fastapi import FastAPI
from app.routes import database, tally

app = FastAPI()

app.include_router(tally.router)
app.include_router(database.router)

@app.get("/")
async def root():
    return {"message": "server is working"}
