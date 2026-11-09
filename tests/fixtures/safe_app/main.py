"""
SAFE TEST APPLICATION FIXTURE.
Used for baseline clean security scans in SENTINEL-X automated test suite.
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Safe Test Application", version="1.0.0")


class Item(BaseModel):
    name: str
    price: float


_DATABASE = {}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/items")
def list_items():
    return list(_DATABASE.values())


@app.post("/items")
def create_item(item: Item):
    _DATABASE[item.name] = item.model_dump()
    return {"status": "created", "item": item}
