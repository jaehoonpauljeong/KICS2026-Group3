from openai import OpenAI

client = OpenAI(api_key="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")

def list_available_models():
    """List all available models using OpenAI API"""
    try:
        models = client.models.list()
        available_models = [model.id for model in models.data]
        return sorted(available_models)
    except Exception as e:
        print(f"Error fetching models: {e}")
        return []

# Usage
print("Available models:")
models = list_available_models()
for model in models:
    print(f"  - {model}")