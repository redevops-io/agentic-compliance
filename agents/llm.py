"""OpenAI-compatible LLM client."""
import os

def get_client():
    base_url = os.environ.get("OPENAI_BASE_URL")
    api_key = os.environ.get("OPENAI_API_KEY")
    model = os.environ.get("MODEL", "gpt-4o-mini")
    try:
        from openai import OpenAI
        return OpenAI(base_url=base_url, api_key=api_key), model
    except Exception:
        return None, model

def chat(messages):
    client, model = get_client()
    if client is None:
        return "LLM unavailable"
    resp = client.chat.completions.create(model=model, messages=messages)
    return resp.choices[0].message.content
