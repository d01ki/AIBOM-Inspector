import os
from openai import OpenAI
from langchain.agents import AgentExecutor, create_react_agent

client = OpenAI()
CHAT_MODEL = os.getenv("CHAT_MODEL", "gpt-4o-mini")
SYSTEM_PROMPT = "You are a terse assistant."


def build_agent():
    agent = create_react_agent(client, tools=[], prompt=SYSTEM_PROMPT)
    return AgentExecutor(agent=agent, tools=[])


def answer(q):
    return client.responses.create(model=CHAT_MODEL, input=q)
