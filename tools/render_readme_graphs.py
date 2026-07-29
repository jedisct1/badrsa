#!/usr/bin/env python3
import csv
import html
import math
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "docs/benchmarks/rsa-operation-profile.csv"
WIDTH = 960
BASELINE = "standard-2048"
COLORS = {BASELINE: "#2563eb", "fixture": "#d45500"}
LABELS = {
    "standard-2048": "Standard 2048-bit",
    "large-modulus-large-exponent": "Large modulus + exponent",
    "large-modulus-large-exponent2": "Large modulus + exponent 2",
    "large-modulus": "Large modulus",
    "maximum-modulus-and-exponent": "Maximum modulus + allowed exponent",
    "maximum-unrestricted-exponent": "Maximum unrestricted exponent",
    "identity-public-exponent": "Identity public exponent",
    "negative-encoded-modulus-and-exponent": "Negative encoded integers",
    "prime-modulus": "Prime modulus",
    "prime-square-modulus": "Prime-square modulus",
    "small-factor-modulus": "Small-factor modulus",
    "oversized-congruent-crt-exponents": "Oversized CRT exponents",
    "inconsistent-crt-coefficient": "Inconsistent CRT coefficient",
    "large-public-exponent": "Large public exponent",
    "combined-worst-case": "Combined worst case",
    "identity-exponents": "Identity exponents",
    "zero-private-exponent": "Zero private exponent",
    "unrelated-private-factors": "Unrelated private factors",
    "two-prime-version-with-other-primes": "Ignored other-prime record",
    "unknown-private-version": "Unknown private version",
    "repeated-prime": "Repeated prime",
}


def position(value, low, high, left, width, logarithmic):
    if logarithmic:
        value = math.log10(value)
        low = math.log10(low)
        high = math.log10(high)
    return left + (value - low) / (high - low) * width


def format_time(seconds):
    if seconds < 1:
        return f"{seconds * 1000:.3f} ms"
    return f"{seconds:.3f} s"


def format_time_ratio(ratio):
    if ratio < 10:
        return f"{ratio:.2f}x"
    if ratio < 100:
        return f"{ratio:.1f}x"
    return f"{ratio:.0f}x"


def format_mib_difference(value):
    rounded = Decimal(str(value)).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP)
    if not rounded:
        return "0.000 MiB"
    return f"{rounded:+f} MiB"


def axis(metric, operation):
    if metric == "time" and operation == "sign":
        ticks = [(value, f"{value}x") for value in (1, 10, 100, 1000, 10000)]
        return 1, 10000, ticks, True
    if metric == "time":
        ticks = [(value / 10, f"{value / 10:.1f}x") for value in range(10, 17)]
        return 1, 1.6, ticks, False
    if operation == "sign":
        ticks = [(value / 100, f"{value / 100:+.2f}") for value in (0, 25, 50, 75, 100)]
        return 0, 1.1, ticks, False
    ticks = [(value / 100, f"{value / 100:+.2f}") for value in (-4, 0, 4, 8)]
    return -0.04, 0.08, ticks, False


def render(operation, metric, rows, output):
    key = "time_median_seconds" if metric == "time" else "rss_median_mib"
    baseline_rows = [row for row in rows if row["case"] == BASELINE]
    if len(baseline_rows) != 1:
        raise ValueError(f"{operation}: expected one standard baseline")
    baseline_row = baseline_rows[0]
    baseline_value = float(baseline_row[key])
    ranked = sorted(
        (row for row in rows if row["case"] != BASELINE),
        key=lambda row: float(row[key]),
        reverse=True,
    )
    display_rows = ranked
    sample_counts = {row["samples"] for row in rows}
    if len(sample_counts) != 1:
        raise ValueError(f"{operation}: inconsistent sample counts")
    samples = sample_counts.pop()

    label_right = 256
    plot_left = 280
    plot_width = 420
    relative_x = 728
    measured_x = 940
    plot_top = 154
    row_gap = 50
    plot_bottom = plot_top + (len(display_rows) - 1) * row_gap
    height = plot_bottom + 94
    low, high, ticks, logarithmic = axis(metric, operation)
    reference_value = 1 if metric == "time" else 0
    baseline_x = position(reference_value, low, high, plot_left, plot_width, logarithmic)
    operation_label = "Verification" if operation == "verify" else "Signing"
    metric_label = "Time" if metric == "time" else "Peak RSS"
    measured_label = "Median time" if metric == "time" else "Median peak RSS"
    scale_label = "logarithmic" if logarithmic else "linear"
    description_metric = "wall time ratio" if metric == "time" else "peak resident memory difference"
    baseline_measured = format_time(baseline_value) if metric == "time" else f"{baseline_value:.3f} MiB"

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" viewBox="0 0 {WIDTH} {height}" role="img" aria-labelledby="title desc">',
        f'<title id="title">RSA {operation_label.lower()} {description_metric} relative to baseline</title>',
        f'<desc id="desc">{description_metric.capitalize()} from reported medians of {samples} fresh processes. Fixtures are compared with a standard 2048-bit RSA control and ranked from highest to lowest.</desc>',
        '<rect width="100%" height="100%" rx="12" fill="#ffffff"/>',
        '<style>text{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;fill:#172033}.title{font-size:24px;font-weight:700}.subtitle{font-size:14px;fill:#556070}.heading{font-size:13px;font-weight:650;fill:#394457}.label{font-size:14px}.value{font-size:14px;font-weight:650}.measured{font-size:13px;fill:#556070}.tick{font-size:12px;fill:#626d7d}.note{font-size:12px;fill:#626d7d}.grid{stroke:#dce2ea;stroke-width:1}.baseline{stroke:#2563eb;stroke-width:2;stroke-dasharray:5 4}</style>',
        f'<text class="title" x="24" y="38">RSA {operation_label} {metric_label} vs. 2048-bit Control</text>',
        f'<text class="subtitle" x="24" y="64">Control median: {baseline_measured} ({"1.00x" if metric == "time" else "0 MiB difference"})</text>',
        f'<text class="heading" x="{plot_left}" y="92">{"Time ratio" if metric == "time" else "RSS difference (MiB)"}</text>',
        f'<text class="heading" x="{relative_x}" y="92">{"Ratio" if metric == "time" else "Difference"}</text>',
        f'<text class="heading" x="{measured_x}" y="92" text-anchor="end">{measured_label}</text>',
    ]

    for index in range(len(display_rows)):
        if index % 2:
            y = plot_top + index * row_gap - 22
            svg.append(f'<rect x="12" y="{y}" width="936" height="44" rx="6" fill="#f6f8fb"/>')
    for value, label in ticks:
        x = position(value, low, high, plot_left, plot_width, logarithmic)
        grid_class = "baseline" if math.isclose(value, reference_value) else "grid"
        svg.extend([
            f'<line class="{grid_class}" x1="{x:.1f}" y1="116" x2="{x:.1f}" y2="{plot_bottom + 22}"/>',
            f'<text class="tick" x="{x:.1f}" y="108" text-anchor="middle">{label}</text>',
        ])

    for index, row in enumerate(display_rows):
        y = plot_top + index * row_gap
        name = row["case"]
        value = float(row[key])
        difference = value - baseline_value
        plot_value = value / baseline_value if metric == "time" else difference
        x = position(plot_value, low, high, plot_left, plot_width, logarithmic)
        color = COLORS["fixture"]
        relative = format_time_ratio(plot_value) if metric == "time" else format_mib_difference(difference)
        measured = format_time(value) if metric == "time" else f"{value:.3f} MiB"
        svg.extend([
            f'<text class="label" x="{label_right}" y="{y + 5}" text-anchor="end">{html.escape(LABELS[name])}</text>',
            f'<line x1="{min(baseline_x, x):.1f}" y1="{y}" x2="{max(baseline_x, x):.1f}" y2="{y}" stroke="{color}" stroke-width="7" stroke-linecap="round"/>',
            f'<circle cx="{x:.1f}" cy="{y}" r="6" fill="{color}" stroke="#ffffff" stroke-width="2"/>',
            f'<text class="value" x="{relative_x}" y="{y + 5}">{relative}</text>',
            f'<text class="measured" x="{measured_x}" y="{y + 5}" text-anchor="end">{measured}</text>',
        ])

    notes = [f"Ratio of {samples}-process medians. {scale_label.capitalize()} scale."]
    if metric == "memory":
        notes = [f"Difference of {samples}-process medians."]
        if any(float(row[key]) < baseline_value for row in display_rows):
            notes.append("Negative values reflect whole-process variation.")
    svg.append(f'<text class="note" x="{plot_left}" y="{height - 26}">{html.escape(" ".join(notes))}</text>')
    svg.append('</svg>')
    output.write_text("\n".join(svg) + "\n", encoding="utf-8")


def main():
    with DATA.open(newline="") as source:
        rows = list(csv.DictReader(source))
    unknown = {row["case"] for row in rows} - LABELS.keys()
    if unknown:
        raise ValueError(f"missing labels: {', '.join(sorted(unknown))}")
    for operation in ("verify", "sign"):
        selected = [row for row in rows if row["operation"] == operation]
        for metric in ("time", "memory"):
            output = DATA.parent / f"rsa-{operation}-{metric}-overhead.svg"
            render(operation, metric, selected, output)


if __name__ == "__main__":
    main()
