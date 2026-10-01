import ollama


def generate_explanation(risk_score, risk_level, signals, webpage):

    signal_text = "\n".join(
        f"- {signal['name']} (+{signal['points']} points)"
        for signal in signals
    )

    prompt = f"""
You are explaining a website security scan.

Risk: {risk_level}
Score: {risk_score}/100

Security signals:
{signal_text if signal_text else "None"}

Write a very short explanation.

If there are signals, explain only the important ones.
If there are no signals, say that no suspicious signals were detected.

Give one safety tip.

Do not discuss page statistics like links, images or scripts unless they are a security signal.

Use this format:

Why: ...
Tip: ...

Keep the answer below 60 words.
"""

    response = ollama.chat(
        model="tinyllama",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response["message"]["content"]