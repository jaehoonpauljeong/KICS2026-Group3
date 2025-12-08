import os
import csv
from collections import Counter

import matplotlib.pyplot as plt
from openai import OpenAI

# Configuration: API key and model
OPENAI_API_KEY = "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"
client = OpenAI(api_key=OPENAI_API_KEY)
DEFAULT_MODEL = "gpt-5-mini"

DATASET_CSV = "intent_classification_dataset.csv"
PREDICTIONS_CSV = "intent_classification_dataset_LLM_predictions_gpt_5_mini.csv"
YANG_CSV = "YANG data model.csv"


def load_yang_context(path: str = YANG_CSV, max_rows: int = 100) -> str:
    """
    Parse the YANG data model CSV and build a compact textual summary
    that can be injected into the classifier system prompt.

    We only keep up to `max_rows` rows to avoid an excessively long prompt.
    """
    lines = []
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= max_rows:
                    break

                path_val = (row.get("Path") or "").strip()
                kind = (row.get("Kind") or "").strip()
                type_val = (row.get("Type (if shown)") or "").strip()
                desc = (row.get("Description") or "").strip()

                if not path_val:
                    continue

                parts = [f"PATH={path_val}"]
                if kind:
                    parts.append(f"KIND={kind}")
                if type_val:
                    parts.append(f"TYPE={type_val}")
                if desc:
                    parts.append(f"DESC={desc}")

                lines.append(" | ".join(parts))
    except FileNotFoundError:
        # If the file is missing, we just skip adding YANG context
        return ""

    if not lines:
        return ""

    return "I2NSF YANG data model fields:\n" + "\n".join(f"- {ln}" for ln in lines)


# Load YANG context once at import time
YANG_CONTEXT = load_yang_context()


def call_openai(system_prompt: str, user_content: str, model: str = DEFAULT_MODEL) -> str:
    """Helper function to call the OpenAI ChatCompletion API and return the response text."""
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ],
        # temperature=0  # you can uncomment this for deterministic outputs
    )
    return response.choices[0].message.content.strip()


def classify_intent_relevance(policy_intent: str, model: str = DEFAULT_MODEL) -> str:
    """
    Classify whether a user intent is suitable for I2NSF network security policy generation.

    Output MUST be exactly one of:
    - 'valid'     -> intent IS a network security / traffic-control policy
    - 'not_valid' -> intent is unrelated / not appropriate for I2NSF policy generation
    """
    system_prompt = (
        "You are a classifier for a network security policy engine based on the I2NSF framework.\n"
        "Your task is to decide whether the user's intent describes a NETWORK SECURITY POLICY that could "
        "reasonably be implemented as an I2NSF policy.\n\n"
        "Label as 'valid' ONLY IF the intent clearly involves one or more of:\n"
        "- Firewall rules (allow/deny/block/pass traffic)\n"
        "- Traffic filtering or inspection (e.g., IDS/IPS, malware, DDoS mitigation)\n"
        "- URL / application / user access control (who can access what/when/where)\n"
        "- Network-level logging/monitoring of flows (copy, mirror, log packets/flows)\n"
        "- Threat intelligence / blacklists / whitelists for network endpoints\n\n"
        "If the intent is about anything else that cannot reasonably be turned into an I2NSF policy, "
        "label it as 'not_valid'.\n\n"
        "IMPORTANT:\n"
        "- Respond with EXACTLY one word: either 'valid' or 'not_valid'.\n"
        "- Do not include explanations or any other text."
    )

    # Inject YANG data model context if available
    if YANG_CONTEXT:
        system_prompt += (
            "\n\nYou are also given the I2NSF YANG data model fields below. "
            "Consider an intent 'valid' only if its entities and actions can reasonably map "
            "to these fields.\n\n"
            f"{YANG_CONTEXT}"
        )

    result = call_openai(system_prompt, policy_intent, model=model)
    return result.strip().lower()


def load_dataset(path: str):
    intents = []
    labels = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            intent = row["intent"].strip()
            label = row["label"].strip().lower()
            if not intent:
                continue
            intents.append(intent)
            labels.append(label)
    return intents, labels


def evaluate_classifier(intents, labels, model: str = DEFAULT_MODEL):
    """
    Run the classifier on all intents and compute TP/FN/FP/TN.

    Returns:
        counts: Counter with TP/FN/FP/TN
        accuracy: float
        y_true: list of true labels
        y_pred: list of predicted labels
    """
    y_true = []
    y_pred = []

    for intent, label in zip(intents, labels):
        print(f"Classifying intent: {intent}")
        pred = classify_intent_relevance(intent, model=model)
        print(f"  True: {label}, Pred: {pred}\n")
        y_true.append(label)
        y_pred.append(pred)

    # Compute counts
    counts = Counter()
    for t, p in zip(y_true, y_pred):
        if t == "valid" and p == "valid":
            counts["TP"] += 1
        elif t == "valid" and p != "valid":
            counts["FN"] += 1
        elif t != "valid" and p == "valid":
            counts["FP"] += 1
        else:
            counts["TN"] += 1

    total = len(y_true)
    accuracy = (counts["TP"] + counts["TN"]) / total if total else 0.0

    print("=== Evaluation Results ===")
    print(f"Total samples: {total}")
    print(f"Accuracy: {accuracy:.3f}")
    print(f"TP (true valid):   {counts['TP']}")
    print(f"FN (missed valid): {counts['FN']}")
    print(f"FP (false valid):  {counts['FP']}")
    print(f"TN (true invalid): {counts['TN']}")

    return counts, accuracy, y_true, y_pred


def save_predictions_csv(path: str, intents, y_true, y_pred):
    """
    Save per-intent predictions to a CSV file.

    Columns:
        intent, true_label, predicted_label, correct
    """
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["intent", "true_label", "predicted_label", "correct"])
        for intent, t, p in zip(intents, y_true, y_pred):
            correct = (t == p)
            writer.writerow([intent, t, p, int(correct)])


def plot_confusion_bars(counts):
    labels = ["TP", "FN", "FP", "TN"]
    values = [counts[l] for l in labels]

    plt.figure()
    plt.bar(labels, values)
    plt.title("Intent Classifier Results")
    plt.xlabel("Category")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    intents, labels = load_dataset(DATASET_CSV)
    counts, accuracy, y_true, y_pred = evaluate_classifier(intents, labels)

    save_predictions_csv(PREDICTIONS_CSV, intents, y_true, y_pred)
    print(f"Saved prediction details to {PREDICTIONS_CSV}")

    plot_confusion_bars(counts)
