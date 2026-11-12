from openai import OpenAI

client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")

messages = [
    {
        "role": "system",
        "content": "You are a patient academic mentor for computer science students. Answer clearly and briefly.",
    }
]

while True:
    user_input = input("User: ").strip()
    if user_input.lower() in ("exit", "quit"):
        break
    if not user_input:
        continue

    messages.append({"role": "user", "content": user_input})
    response = client.chat.completions.create(model="qwen2.5:1.5b", temperature=0.2, messages=messages)
    reply = response.choices[0].message.content
    print(f"Assistant: {reply}\n")
    messages.append({"role": "assistant", "content": reply})
