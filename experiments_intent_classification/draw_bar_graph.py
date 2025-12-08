import matplotlib.pyplot as plt

models = ["GPT-4o mini", "GPT-5 mini"]
correct = [91, 97]  # number of correctly classified samples (out of 100)

plt.figure(figsize=(6, 4))

# Narrower bars
bars = plt.bar(models, correct, width=0.4)

# Add value labels on top of bars
for bar, val in zip(bars, correct):
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2.0,
             height + 0.8,          # small offset above bar
             f"{val}",
             ha="center", va="bottom")

plt.ylim(0, 103)  # bit of headroom so labels don't touch the top
plt.ylabel("Number of correctly classified intents")
plt.title("Intent Relevance Classifier Performance")
plt.tight_layout()
plt.savefig("results.png")
plt.show()
