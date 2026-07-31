"""Risky candidate: external content now changes the privileged instruction."""

from fastapi import FastAPI
from openai import OpenAI

app = FastAPI()
client = OpenAI()
POLICY = "Follow the internal support policy."


@app.post("/chat")
def chat(message: str) -> object:
    messages = [
        {"role": "system", "content": POLICY + message},
        {"role": "user", "content": message},
    ]
    return client.chat.completions.create(model="gpt-4.1", messages=messages)
