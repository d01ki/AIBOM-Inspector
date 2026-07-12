"""Deliberately vulnerable demo app for AIBOM Inspector.

This file exists only as a scan target. It is never executed by the scanner.
It intentionally exhibits AI supply-chain smells (unpinned models, pickle
weights, trust_remote_code, hardcoded prompt) for demo/testing purposes.
"""

import openai
from datasets import load_dataset
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline

# Unpinned model reference (no revision) — provenance risk.
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")

# trust_remote_code + a look-alike (typosquat-ish) org/name.
model = AutoModelForCausalLM.from_pretrained(
    "acme-ai/llama-7b-hf", trust_remote_code=True
)

# Pinned reference (good) for contrast.
sentiment = pipeline("sentiment-analysis", model="distilbert/distilbert-base-uncased")

# Dataset with no provenance metadata.
train_ds = load_dataset("imdb")

# Hardcoded system prompt.
SYSTEM_PROMPT = "You are a helpful assistant. Always answer truthfully."

client = openai.OpenAI(base_url="https://api.openai.com/v1")


def summarize(text: str) -> str:
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
    )
    return resp.choices[0].message.content
