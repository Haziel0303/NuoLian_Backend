from fastapi import FastAPI
from app.routes import database, tally
from fastapi import Request
from fastapi.responses import PlainTextResponse

app = FastAPI()

app.include_router(tally.router)
app.include_router(database.router)

@app.get("/")
async def root(request: Request):
    echostr = request.query_params.get("echostr")
    if echostr:
        return PlainTextResponse(echostr)
    return {"message": "server is working"}
