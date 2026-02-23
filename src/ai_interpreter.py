from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
from typing import Dict
import torch

# Load tokenizer and model properly for encoder-decoder architecture
tokenizer = AutoTokenizer.from_pretrained("google/flan-t5-base")
model = AutoModelForSeq2SeqLM.from_pretrained("google/flan-t5-base")


def explain_threat(event: Dict) -> str:
    """
    Generate structured cybersecurity analysis for suspicious firewall activity.
    """

    src = event.get("SRC", "Unknown")
    dst = event.get("DST", "Unknown")
    proto = event.get("PROTO", "Unknown")
    dpt = event.get("DPT", "Unknown")
    count = event.get("count", "Unknown")

    prompt = (
        "Act as a senior cybersecurity analyst writing a formal incident report.\n\n"
        f"Source IP: {src}\n"
        f"Destination IP: {dst}\n"
        f"Protocol: {proto}\n"
        f"Destination Port: {dpt}\n"
        f"Repeated Attempts: {count}\n\n"
        "Write a detailed 6-8 sentence analysis describing:\n"
        "- The attacker behavior\n"
        "- Likely objective\n"
        "- Risk severity\n"
        "- Attack lifecycle phase\n"
        "- Defensive mitigation steps\n\n"
        "Use formal SOC reporting language."
    )
    

    inputs = tokenizer(prompt, return_tensors="pt")

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=250,
            do_sample=True,
            temperature=0.7,
            top_p=0.9,
            repetition_penalty=1.2
        )
        

    result = tokenizer.decode(outputs[0], skip_special_tokens=True)

    return result.strip()