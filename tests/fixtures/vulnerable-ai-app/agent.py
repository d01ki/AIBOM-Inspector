"""A minimal LangChain agent — scan target only, never executed."""

from langchain.agents import AgentExecutor, create_react_agent
from langchain_huggingface import HuggingFacePipeline

llm = HuggingFacePipeline.from_pretrained("mistralai/Mistral-7B-Instruct-v0.2")

agent = create_react_agent(llm, tools=[], prompt="prompts/agent_system.prompt")
executor = AgentExecutor(agent=agent, tools=[])
