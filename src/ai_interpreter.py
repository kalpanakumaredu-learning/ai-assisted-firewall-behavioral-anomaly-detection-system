from transformers import pipeline
from typing import Dict

# Load lightweight local model
llm = pipeline("text-generation", model="google/flan-t5-base")

def explain_threat(event: Dict) -> str:
    """
    Returns a detailed narrative explanation for a suspicious firewall event.
    Produces a multi-sentence human-readable cybersecurity assessment.
    """

    src = event.get("SRC", "Unknown")
    dst = event.get("DST", "Unknown")
    proto = event.get("PROTO", "Unknown")
    dpt = event.get("DPT", "Unknown")
    count = event.get("count", "Unknown")

    prompt = f"""
You are a senior cybersecurity analyst.
Analyze the following network event and provide a detailed security explanation (6-8 sentences):

Source IP: {src}
Destination IP: {dst}
Protocol: {proto}
Destination Port: {dpt}
Repeated Attempts: {count}

Your explanation MUST include:
1. The likely attacker behavior or technique.
2. A possible motive for the repeated attempts.
3. The potential security risk if ignored.
4. How this behavior fits into the attack kill chain.
5. Recommended defensive actions.

Write in clear professional incident-report language.
    """

    response = llm(prompt, max_length=200)[0]["generated_text"]
    return response.strip()
