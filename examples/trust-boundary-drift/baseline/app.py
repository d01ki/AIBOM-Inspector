"""Safe baseline: external content stays in the user message."""

from fastapi import FastAPI
from openai import OpenAI

app = FastAPI()
client = OpenAI()
POLICY = "Follow the internal support policy."


@app.post("/chat")
def chat(message: str) -> object:
    messages = [
        {"role": "system", "content": POLICY},
        {"role": "user", "content": message},
    ]
    return client.chat.completions.create(model="gpt-4.1", messages=messages)
