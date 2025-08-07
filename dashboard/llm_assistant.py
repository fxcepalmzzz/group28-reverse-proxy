from llama_cpp import Llama

# Load the model from disk (Q2_K quantized TinyLlama)
llm = Llama(
    model_path="/root/models/tinyllama-1.1b-chat-v1.0.Q2_K.gguf",
    n_ctx=2048,
    n_batch=64,
    n_threads=4,
    chat_format="chatml"  # Required for this model
)

def ask_llm(user_question):
    messages = [
        {"role": "system", "content": "You are a helpful SOC assistant. Answer questions about logs, cybersecurity, NGINX, WAF, and incident response."},
        {"role": "user", "content": user_question}
    ]

    response = llm.create_chat_completion(
        messages=messages,
        temperature=0.5,
        max_tokens=512
    )
    return response["choices"][0]["message"]["content"].strip()
