import matplotlib.pyplot as plt
import matplotlib as mpl
import numpy as np

# === Global font sizes ===
mpl.rcParams.update({
    "font.size": 14,        # base font size
    "axes.titlesize": 20,   # figure/axes titles
    "axes.labelsize": 16,   # x/y axis labels
    "xtick.labelsize": 14,  # x tick labels
    "ytick.labelsize": 14,  # y tick labels
    "legend.fontsize": 14,  # legend text
})

# Raw scores from 3 experiments each
scores = {
    "Baseline LLM (GPT-4o mini)": [0, 0, 0],
    "Prompt Ensembling (GPT-4o mini)": [23, 32, 24],
    "Prompt Ensembling (GPT-5 mini)": [41, 43, 45],
}

# Compute averages
methods = list(scores.keys())
averages = [np.mean(scores[m]) for m in methods]

x = np.arange(len(methods))

fig, ax = plt.subplots(figsize=(9, 6))
bars = ax.bar(x, averages, width=0.55)

ax.set_ylabel("Average # of Correct XML Policies (n=3)")
ax.set_title("Average Syntactic Correctness of Generated XML Policies")
ax.set_xticks(x)
ax.set_xticklabels(methods, rotation=0)  # keep straight; font size from rcParams
ax.set_ylim(0, max(averages) * 1.2 if max(averages) > 0 else 1)

# Larger annotation fonts
for rect, val in zip(bars, averages):
    ax.annotate(f"{val:.1f}",
                xy=(rect.get_x() + rect.get_width() / 2, rect.get_height()),
                xytext=(0, 7), textcoords="offset points",
                ha="center", va="bottom", fontsize=14)

plt.tight_layout()
plt.show()
