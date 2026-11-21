"""Turn results/results.csv into charts for the paper and slides.

Usage:
    python src/plot_results.py
Writes results/memory.png, results/false_positive_rate.png, results/lookup_time.png
"""

import csv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# One color per structure, used the same way in every chart
COLORS = {"Python set": "#2a78d6", "Bloom filter 1.0%": "#eb6834", "Bloom filter 0.1%": "#1baf7a"}
LABELS = {"Python set": "Python set (hash table)", "Bloom filter 1.0%": "Bloom filter, 1% target",
          "Bloom filter 0.1%": "Bloom filter, 0.1% target"}
INK, MUTED, GRID = "#1f1f1e", "#6b6a64", "#e4e3de"


def load_results():
    with open("results/results.csv") as f:
        rows = list(csv.DictReader(f))
    sizes = sorted({int(r["n"]) for r in rows})
    data = {}   # data[structure][n] = row
    for r in rows:
        data.setdefault(r["structure"], {})[int(r["n"])] = r
    return sizes, data


def clean_style(ax, title, ylabel, title_pad=30):
    ax.set_title(title, loc="left", fontsize=12, color=INK, pad=title_pad)
    ax.set_ylabel(ylabel, color=MUTED, fontsize=10)
    ax.tick_params(colors=MUTED, labelsize=9, length=0)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def grouped_bars(ax, sizes, data, structures, value, label):
    """Draw one group of bars per list size, one bar per structure, with the value on top."""
    width = 0.26
    for i, s in enumerate(structures):
        xs = [j + (i - (len(structures) - 1) / 2) * (width + 0.02) for j in range(len(sizes))]
        vals = [value(data[s][n]) for n in sizes]
        bars = ax.bar(xs, vals, width, color=COLORS[s], label=LABELS[s], edgecolor="white", linewidth=1)
        for bar, v in zip(bars, vals):
            ax.annotate(label(v), (bar.get_x() + bar.get_width() / 2, bar.get_height()), ha="center",
                        va="bottom", fontsize=8, color=INK, xytext=(0, 2), textcoords="offset points")
    ax.set_xticks(range(len(sizes)), [f"{n:,} hashes" for n in sizes])
    ax.legend(frameon=False, fontsize=9, loc="lower left", ncol=3, bbox_to_anchor=(0, 1.0))


def memory_chart(sizes, data):
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=200)
    grouped_bars(ax, sizes, data, list(COLORS), lambda r: int(r["memory_bytes"]) / 1e6,
                 lambda v: f"{v:.2f} MB" if v >= 0.1 else f"{v * 1000:.0f} KB")
    ax.set_yscale("log")   # log scale, because the set is about 100 times bigger
    clean_style(ax, "Memory to store the breached-password list", "Megabytes (log scale)")
    fig.tight_layout()
    fig.savefig("results/memory.png")
    plt.close(fig)


def false_positive_chart(sizes, data):
    # Two panels, because 1% and 0.1% are ten times apart and would squash each other on one axis
    fig, axes = plt.subplots(1, 2, figsize=(9, 4.2), dpi=200)
    for ax, s, target in zip(axes, ["Bloom filter 1.0%", "Bloom filter 0.1%"], [1.0, 0.1]):
        measured = [float(data[s][n]["measured_fp_rate"]) * 100 for n in sizes]
        theory = [float(data[s][n]["theory_fp_rate"]) * 100 for n in sizes]
        bars = ax.bar(range(len(sizes)), measured, 0.55, color=COLORS[s], label="Measured")
        for bar, v, t in zip(bars, measured, theory):
            top = max(v, t)   # put the label above whichever is higher, the bar or the theory mark
            ax.annotate(f"{v:.3f}%", (bar.get_x() + bar.get_width() / 2, top), ha="center",
                        va="bottom", fontsize=8, color=INK, xytext=(0, 6), textcoords="offset points")
        ax.scatter(range(len(sizes)), theory, marker="_", s=900, color=INK, linewidths=2, zorder=3,
                   label="Theory")
        ax.set_xticks(range(len(sizes)), [f"{n:,}" for n in sizes])
        ax.set_xlabel("Hashes in the list", color=MUTED, fontsize=9)
        ax.set_ylim(0, target * 1.35)
        clean_style(ax, LABELS[s], "Safe passwords wrongly flagged (%)" if target == 1.0 else "", title_pad=12)
        ax.title.set_fontsize(10)
    axes[0].legend(frameon=False, fontsize=9, loc="upper center", ncol=2)
    fig.suptitle("False-positive rate: measured vs theory", x=0.02, ha="left", fontsize=12, color=INK)
    fig.tight_layout()
    fig.savefig("results/false_positive_rate.png")
    plt.close(fig)


def lookup_chart(sizes, data):
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=200)
    grouped_bars(ax, sizes, data, list(COLORS), lambda r: float(r["microseconds_per_check"]),
                 lambda v: f"{v:.2f}")
    clean_style(ax, "Average time to check one password", "Microseconds per lookup")
    fig.tight_layout()
    fig.savefig("results/lookup_time.png")
    plt.close(fig)


def main():
    sizes, data = load_results()
    memory_chart(sizes, data)
    false_positive_chart(sizes, data)
    lookup_chart(sizes, data)
    print("Saved results/memory.png, results/false_positive_rate.png, results/lookup_time.png")


if __name__ == "__main__":
    main()