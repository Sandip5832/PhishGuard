import os
import re
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


# ============================================================
# PHISHGUARD - PROFESSIONAL COMPACT DASHBOARD
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ANALYZER_FILE = os.path.join(
    BASE_DIR,
    "src",
    "analyze_email.py"
)

REPORT_FILE = os.path.join(
    BASE_DIR,
    "reports",
    "phishguard_report.txt"
)


# ============================================================
# COLORS
# ============================================================

BG = "#0b1120"
CARD = "#111827"
CARD_2 = "#172033"
BORDER = "#263247"

TEXT = "#f1f5f9"
MUTED = "#94a3b8"

BLUE = "#38bdf8"
BLUE_DARK = "#0ea5e9"

GREEN = "#22c55e"
YELLOW = "#eab308"
ORANGE = "#f97316"
RED = "#ef4444"

WHITE = "#ffffff"


# ============================================================
# ROOT WINDOW
# ============================================================

root = tk.Tk()

root.title("PhishGuard - Email Security Analyzer")

root.geometry("1280x820")
root.minsize(1050, 680)

root.configure(bg=BG)


# ============================================================
# VARIABLES
# ============================================================

selected_file = tk.StringVar(value="")

status_var = tk.StringVar(
    value="Ready - Select an email file to begin"
)

risk_var = tk.StringVar(
    value="NOT ANALYZED"
)

score_var = tk.StringVar(
    value="0"
)

file_name_var = tk.StringVar(
    value="No email selected"
)

file_path_var = tk.StringVar(
    value="Select a .eml file for analysis"
)

high_var = tk.StringVar(value="0")
medium_var = tk.StringVar(value="0")
low_var = tk.StringVar(value="0")
total_var = tk.StringVar(value="0")

recommendation_var = tk.StringVar(
    value="Select an email and run the analysis to receive a security recommendation."
)


# ============================================================
# FONT
# ============================================================

FONT = "Segoe UI"


def app_font(size=10, weight="normal"):
    return (FONT, size, weight)


# ============================================================
# MAIN SCROLL AREA
# ============================================================

outer_frame = tk.Frame(
    root,
    bg=BG
)

outer_frame.pack(
    fill="both",
    expand=True
)


canvas = tk.Canvas(
    outer_frame,
    bg=BG,
    highlightthickness=0,
    bd=0
)

scrollbar = tk.Scrollbar(
    outer_frame,
    orient="vertical",
    command=canvas.yview,
    bg=CARD,
    troughcolor=BG,
    activebackground=BLUE,
    relief="flat"
)

scrollbar.pack(
    side="right",
    fill="y"
)

canvas.pack(
    side="left",
    fill="both",
    expand=True
)

canvas.configure(
    yscrollcommand=scrollbar.set
)


main_frame = tk.Frame(
    canvas,
    bg=BG
)

canvas_window = canvas.create_window(
    (0, 0),
    window=main_frame,
    anchor="nw"
)


def update_scroll_region(event=None):
    canvas.configure(
        scrollregion=canvas.bbox("all")
    )


def resize_canvas_window(event):
    canvas.itemconfig(
        canvas_window,
        width=event.width
    )


main_frame.bind(
    "<Configure>",
    update_scroll_region
)

canvas.bind(
    "<Configure>",
    resize_canvas_window
)


# ============================================================
# MOUSE WHEEL
# ============================================================

def mouse_wheel(event):
    try:
        canvas.yview_scroll(
            int(-1 * (event.delta / 120)),
            "units"
        )
    except Exception:
        pass


def mouse_wheel_up(event):
    canvas.yview_scroll(
        -3,
        "units"
    )


def mouse_wheel_down(event):
    canvas.yview_scroll(
        3,
        "units"
    )


root.bind_all(
    "<MouseWheel>",
    mouse_wheel
)

root.bind_all(
    "<Button-4>",
    mouse_wheel_up
)

root.bind_all(
    "<Button-5>",
    mouse_wheel_down
)


def page_up(event=None):
    canvas.yview_scroll(
        -8,
        "units"
    )
    return "break"


def page_down(event=None):
    canvas.yview_scroll(
        8,
        "units"
    )
    return "break"


root.bind_all(
    "<Prior>",
    page_up
)

root.bind_all(
    "<Next>",
    page_down
)


# ============================================================
# CARD FUNCTION
# ============================================================

def create_card(parent, padx=25, pady=5):

    frame = tk.Frame(
        parent,
        bg=CARD,
        highlightbackground=BORDER,
        highlightthickness=1
    )

    frame.pack(
        fill="x",
        padx=padx,
        pady=pady
    )

    return frame


def create_title(parent, title, subtitle=None):

    title_label = tk.Label(
        parent,
        text=title,
        bg=CARD,
        fg=TEXT,
        font=app_font(15, "bold"),
        anchor="w"
    )

    title_label.pack(
        fill="x",
        pady=(0, 3)
    )

    if subtitle:

        subtitle_label = tk.Label(
            parent,
            text=subtitle,
            bg=CARD,
            fg=MUTED,
            font=app_font(8),
            anchor="w",
            justify="left"
        )

        subtitle_label.pack(
            fill="x",
            pady=(0, 8)
        )


def clear_text(widget):

    widget.config(
        state="normal"
    )

    widget.delete(
        "1.0",
        "end"
    )

    widget.config(
        state="disabled"
    )


# ============================================================
# HEADER
# ============================================================

header = tk.Frame(
    main_frame,
    bg=BG
)

header.pack(
    fill="x",
    padx=30,
    pady=(15, 5)
)


header_left = tk.Frame(
    header,
    bg=BG
)

header_left.pack(
    side="left",
    fill="x",
    expand=True
)


logo = tk.Label(
    header_left,
    text="PHISHGUARD",
    bg=BG,
    fg=BLUE,
    font=app_font(25, "bold"),
    anchor="w"
)

logo.pack(
    anchor="w"
)


tagline = tk.Label(
    header_left,
    text="Email Phishing Detection & Security Analysis",
    bg=BG,
    fg=MUTED,
    font=app_font(10),
    anchor="w"
)

tagline.pack(
    anchor="w"
)


status_header = tk.Frame(
    header,
    bg=CARD
)

status_header.pack(
    side="right"
)


status_dot = tk.Label(
    status_header,
    text="●",
    bg=CARD,
    fg=GREEN,
    font=app_font(10)
)

status_dot.pack(
    side="left",
    padx=(10, 4),
    pady=8
)


status_text = tk.Label(
    status_header,
    text="ENGINE READY",
    bg=CARD,
    fg=TEXT,
    font=app_font(8, "bold")
)

status_text.pack(
    side="left",
    padx=(0, 10)
)


# ============================================================
# FILE SELECTION
# ============================================================

file_card = create_card(
    main_frame,
    30,
    5
)

create_title(
    file_card,
    "Email Analysis",
    "Choose an .eml email file and run PhishGuard's detection engine."
)


file_row = tk.Frame(
    file_card,
    bg=CARD
)

file_row.pack(
    fill="x"
)


file_info = tk.Frame(
    file_row,
    bg=CARD
)

file_info.pack(
    side="left",
    fill="x",
    expand=True
)


file_name_label = tk.Label(
    file_info,
    textvariable=file_name_var,
    bg=CARD,
    fg=TEXT,
    font=app_font(10, "bold"),
    anchor="w"
)

file_name_label.pack(
    fill="x"
)


file_path_label = tk.Label(
    file_info,
    textvariable=file_path_var,
    bg=CARD,
    fg=MUTED,
    font=app_font(7),
    anchor="w"
)

file_path_label.pack(
    fill="x"
)


button_frame = tk.Frame(
    file_row,
    bg=CARD
)

button_frame.pack(
    side="right",
    padx=(10, 0)
)


# ============================================================
# FILE SELECTION FUNCTION
# ============================================================

def select_email():

    file_path = filedialog.askopenfilename(
        title="Select Email File",
        filetypes=[
            ("Email Files", "*.eml"),
            ("All Files", "*.*")
        ]
    )

    if not file_path:
        return

    selected_file.set(
        file_path
    )

    file_name_var.set(
        os.path.basename(file_path)
    )

    file_path_var.set(
        file_path
    )

    analyze_button.config(
        state="normal"
    )

    status_var.set(
        "Email selected - Ready for analysis"
    )

    status_dot.config(
        fg=BLUE
    )

    status_text.config(
        text="EMAIL SELECTED"
    )


# ============================================================
# BUTTONS
# ============================================================

select_button = tk.Button(
    button_frame,
    text="SELECT EMAIL",
    command=select_email,
    bg=BLUE_DARK,
    fg=WHITE,
    activebackground=BLUE,
    activeforeground=WHITE,
    font=app_font(8, "bold"),
    relief="flat",
    bd=0,
    padx=15,
    pady=8,
    cursor="hand2"
)

select_button.pack(
    side="left",
    padx=3
)


analyze_button = tk.Button(
    button_frame,
    text="ANALYZE",
    command=lambda: run_analysis(),
    bg="#1d4ed8",
    fg=WHITE,
    activebackground=BLUE,
    activeforeground=WHITE,
    font=app_font(8, "bold"),
    relief="flat",
    bd=0,
    padx=15,
    pady=8,
    cursor="hand2",
    state="disabled"
)

analyze_button.pack(
    side="left",
    padx=3
)


# ============================================================
# RESET
# ============================================================

def reset_dashboard():

    selected_file.set("")

    file_name_var.set(
        "No email selected"
    )

    file_path_var.set(
        "Select a .eml file for analysis"
    )

    high_var.set("0")
    medium_var.set("0")
    low_var.set("0")
    total_var.set("0")

    score_var.set("0")

    risk_var.set(
        "NOT ANALYZED"
    )

    recommendation_var.set(
        "Select an email and run the analysis to receive a security recommendation."
    )

    score_progress["value"] = 0

    risk_badge.config(
        text="NOT ANALYZED",
        fg=MUTED
    )

    score_value_label.config(
        fg=BLUE
    )

    clear_text(
        content_text
    )

    clear_text(
        header_text
    )

    clear_text(
        url_text
    )

    clear_text(
        full_output_text
    )

    clear_text(
        breakdown_text
    )

    analyze_button.config(
        state="disabled"
    )

    status_var.set(
        "Ready - Select an email to begin"
    )

    status_dot.config(
        fg=GREEN
    )

    status_text.config(
        text="ENGINE READY"
    )

    canvas.yview_moveto(
        0
    )


reset_button = tk.Button(
    button_frame,
    text="RESET",
    command=reset_dashboard,
    bg=CARD_2,
    fg=TEXT,
    activebackground=BORDER,
    activeforeground=WHITE,
    font=app_font(8, "bold"),
    relief="flat",
    bd=0,
    padx=15,
    pady=8,
    cursor="hand2"
)

reset_button.pack(
    side="left",
    padx=3
)


# ============================================================
# SECURITY DASHBOARD
# ============================================================

summary_card = create_card(
    main_frame,
    30,
    5
)

create_title(
    summary_card,
    "Security Dashboard",
    "Overall phishing assessment generated from email content, headers and URLs."
)


dashboard_row = tk.Frame(
    summary_card,
    bg=CARD
)

dashboard_row.pack(
    fill="x"
)


# ============================================================
# SCORE CARD
# ============================================================

score_frame = tk.Frame(
    dashboard_row,
    bg=CARD_2,
    highlightbackground=BORDER,
    highlightthickness=1
)

score_frame.pack(
    side="left",
    fill="both",
    expand=True,
    padx=(0, 5)
)


tk.Label(
    score_frame,
    text="PHISHING SCORE",
    bg=CARD_2,
    fg=MUTED,
    font=app_font(8, "bold")
).pack(
    pady=(8, 1)
)


score_value_label = tk.Label(
    score_frame,
    textvariable=score_var,
    bg=CARD_2,
    fg=BLUE,
    font=app_font(30, "bold")
)

score_value_label.pack()


tk.Label(
    score_frame,
    text="/ 100",
    bg=CARD_2,
    fg=MUTED,
    font=app_font(8)
).pack()


style = ttk.Style()

try:
    style.theme_use("clam")
except Exception:
    pass


style.configure(
    "TProgressbar",
    troughcolor="#0b1120",
    background=BLUE,
    bordercolor="#0b1120",
    lightcolor=BLUE,
    darkcolor=BLUE
)


score_progress = ttk.Progressbar(
    score_frame,
    orient="horizontal",
    mode="determinate",
    maximum=100,
    length=200
)

score_progress.pack(
    padx=15,
    pady=(4, 9)
)


# ============================================================
# RISK CARD
# ============================================================

risk_frame = tk.Frame(
    dashboard_row,
    bg=CARD_2,
    highlightbackground=BORDER,
    highlightthickness=1
)

risk_frame.pack(
    side="left",
    fill="both",
    expand=True,
    padx=5
)


tk.Label(
    risk_frame,
    text="OVERALL RISK",
    bg=CARD_2,
    fg=MUTED,
    font=app_font(8, "bold")
).pack(
    pady=(8, 7)
)


risk_badge = tk.Label(
    risk_frame,
    text="NOT ANALYZED",
    bg=CARD,
    fg=MUTED,
    font=app_font(13, "bold"),
    padx=15,
    pady=7
)

risk_badge.pack(
    pady=(0, 7)
)


tk.Label(
    risk_frame,
    text="Determined by detection engine",
    bg=CARD_2,
    fg=MUTED,
    font=app_font(7)
).pack(
    pady=(0, 10)
)


# ============================================================
# THREAT FINDINGS
# ============================================================

counts_frame = tk.Frame(
    dashboard_row,
    bg=CARD_2,
    highlightbackground=BORDER,
    highlightthickness=1
)

counts_frame.pack(
    side="left",
    fill="both",
    expand=True,
    padx=(5, 0)
)


tk.Label(
    counts_frame,
    text="THREAT FINDINGS",
    bg=CARD_2,
    fg=MUTED,
    font=app_font(8, "bold")
).pack(
    pady=(8, 5)
)


count_grid = tk.Frame(
    counts_frame,
    bg=CARD_2
)

count_grid.pack(
    fill="x",
    padx=10
)


for i in range(4):
    count_grid.columnconfigure(
        i,
        weight=1
    )


def make_count(
    parent,
    column,
    title,
    variable,
    color
):

    frame = tk.Frame(
        parent,
        bg=CARD_2
    )

    frame.grid(
        row=0,
        column=column,
        sticky="nsew",
        padx=2
    )

    tk.Label(
        frame,
        text=title,
        bg=CARD_2,
        fg=color,
        font=app_font(7, "bold")
    ).pack()

    tk.Label(
        frame,
        textvariable=variable,
        bg=CARD_2,
        fg=TEXT,
        font=app_font(18, "bold")
    ).pack(
        pady=(1, 4)
    )


make_count(
    count_grid,
    0,
    "HIGH",
    high_var,
    RED
)

make_count(
    count_grid,
    1,
    "MEDIUM",
    medium_var,
    ORANGE
)

make_count(
    count_grid,
    2,
    "LOW",
    low_var,
    GREEN
)

make_count(
    count_grid,
    3,
    "TOTAL",
    total_var,
    BLUE
)


# ============================================================
# RECOMMENDATION
# ============================================================

recommendation_card = create_card(
    main_frame,
    30,
    5
)

create_title(
    recommendation_card,
    "Security Recommendation"
)


recommendation_box = tk.Frame(
    recommendation_card,
    bg=CARD_2,
    highlightbackground=BORDER,
    highlightthickness=1
)

recommendation_box.pack(
    fill="x"
)


recommendation_label = tk.Label(
    recommendation_box,
    textvariable=recommendation_var,
    bg=CARD_2,
    fg=TEXT,
    font=app_font(8),
    justify="left",
    anchor="w",
    wraplength=1050
)

recommendation_label.pack(
    fill="x",
    padx=15,
    pady=8
)


# ============================================================
# DETAILED ANALYSIS
# ============================================================

details_card = create_card(
    main_frame,
    30,
    5
)

create_title(
    details_card,
    "Detailed Analysis",
    "Review evidence detected in the email content, headers and URLs."
)


# ============================================================
# NOTEBOOK
# ============================================================

style.configure(
    "TNotebook",
    background=CARD,
    borderwidth=0
)

style.configure(
    "TNotebook.Tab",
    background=CARD_2,
    foreground=MUTED,
    padding=(14, 7),
    font=app_font(8, "bold")
)

style.map(
    "TNotebook.Tab",
    background=[
        ("selected", BLUE_DARK)
    ],
    foreground=[
        ("selected", WHITE)
    ]
)


notebook = ttk.Notebook(
    details_card
)

notebook.pack(
    fill="x"
)


# ============================================================
# TEXT WIDGET
# ============================================================

def create_analysis_text(parent):

    text = tk.Text(
        parent,
        height=11,
        bg="#0a0f1c",
        fg=TEXT,
        insertbackground=WHITE,
        selectbackground=BLUE_DARK,
        selectforeground=WHITE,
        relief="flat",
        bd=0,
        wrap="word",
        font=("Consolas", 8),
        padx=12,
        pady=10
    )

    text.pack(
        fill="x",
        padx=2,
        pady=2
    )

    text.tag_configure(
        "high",
        foreground=RED,
        font=("Consolas", 8, "bold")
    )

    text.tag_configure(
        "medium",
        foreground=ORANGE,
        font=("Consolas", 8, "bold")
    )

    text.tag_configure(
        "low",
        foreground=GREEN,
        font=("Consolas", 8, "bold")
    )

    text.tag_configure(
        "heading",
        foreground=BLUE,
        font=("Consolas", 9, "bold")
    )

    text.tag_configure(
        "label",
        foreground=MUTED,
        font=("Consolas", 8, "bold")
    )

    text.tag_configure(
        "evidence",
        foreground="#cbd5e1"
    )

    text.config(
        state="disabled"
    )

    return text


# ============================================================
# CONTENT TAB
# ============================================================

content_tab = tk.Frame(
    notebook,
    bg="#0a0f1c"
)

notebook.add(
    content_tab,
    text="CONTENT SECURITY"
)

content_text = create_analysis_text(
    content_tab
)


# ============================================================
# HEADER TAB
# ============================================================

header_tab = tk.Frame(
    notebook,
    bg="#0a0f1c"
)

notebook.add(
    header_tab,
    text="HEADER SECURITY"
)

header_text = create_analysis_text(
    header_tab
)


# ============================================================
# URL TAB
# ============================================================

url_tab = tk.Frame(
    notebook,
    bg="#0a0f1c"
)

notebook.add(
    url_tab,
    text="URL SECURITY"
)

url_text = create_analysis_text(
    url_tab
)


# ============================================================
# COMPLETE OUTPUT TAB
# ============================================================

full_output_tab = tk.Frame(
    notebook,
    bg="#0a0f1c"
)

notebook.add(
    full_output_tab,
    text="COMPLETE OUTPUT"
)

full_output_text = create_analysis_text(
    full_output_tab
)


# ============================================================
# SCORE BREAKDOWN
# ============================================================

breakdown_card = create_card(
    main_frame,
    30,
    5
)

create_title(
    breakdown_card,
    "Score Breakdown",
    "Detection engine weighting: HIGH = 25, MEDIUM = 10, LOW = 5."
)


breakdown_text = create_analysis_text(
    breakdown_card
)

breakdown_text.config(
    height=6
)


# ============================================================
# REPORT SECTION
# ============================================================

report_card = create_card(
    main_frame,
    30,
    5
)

create_title(
    report_card,
    "Generated Report",
    "The analysis report is automatically saved in the reports folder."
)


report_row = tk.Frame(
    report_card,
    bg=CARD
)

report_row.pack(
    fill="x"
)


report_path_label = tk.Label(
    report_row,
    text=REPORT_FILE,
    bg=CARD,
    fg=MUTED,
    font=("Consolas", 7),
    anchor="w"
)

report_path_label.pack(
    side="left",
    fill="x",
    expand=True
)


# ============================================================
# OPEN REPORT
# ============================================================

def open_report():

    if not os.path.exists(REPORT_FILE):

        messagebox.showwarning(
            "Report Not Found",
            "No report has been generated yet.\n\n"
            "Run an email analysis first."
        )

        return

    try:

        if os.name == "nt":

            os.startfile(
                REPORT_FILE
            )

        elif sys.platform == "darwin":

            subprocess.Popen(
                ["open", REPORT_FILE]
            )

        else:

            subprocess.Popen(
                ["xdg-open", REPORT_FILE]
            )

    except Exception as e:

        messagebox.showerror(
            "Error",
            f"Could not open report.\n\n{e}"
        )


open_report_button = tk.Button(
    report_row,
    text="OPEN REPORT",
    command=open_report,
    bg=CARD_2,
    fg=TEXT,
    activebackground=BLUE_DARK,
    activeforeground=WHITE,
    font=app_font(8, "bold"),
    relief="flat",
    bd=0,
    padx=15,
    pady=7,
    cursor="hand2"
)

open_report_button.pack(
    side="right"
)


# ============================================================
# STATUS BAR
# ============================================================

status_bar = tk.Frame(
    main_frame,
    bg="#070b14",
    height=35
)

status_bar.pack(
    fill="x",
    padx=30,
    pady=(5, 15)
)

status_bar.pack_propagate(
    False
)


tk.Label(
    status_bar,
    text="STATUS",
    bg="#070b14",
    fg=BLUE,
    font=app_font(7, "bold")
).pack(
    side="left",
    padx=(12, 6)
)


tk.Label(
    status_bar,
    textvariable=status_var,
    bg="#070b14",
    fg=MUTED,
    font=app_font(7)
).pack(
    side="left"
)


tk.Label(
    status_bar,
    text="PhishGuard",
    bg="#070b14",
    fg=MUTED,
    font=app_font(7)
).pack(
    side="right",
    padx=12
)


# ============================================================
# PARSING FUNCTIONS
# ============================================================

def get_section(
    output,
    start_marker,
    end_marker=None
):

    lines = output.splitlines()

    start_index = -1
    end_index = len(lines)

    for i, line in enumerate(lines):

        stripped = line.strip()

        if stripped.upper() == start_marker.upper():

            start_index = i + 1
            break

    if start_index == -1:
        return []

    if end_marker:

        for i in range(
            start_index,
            len(lines)
        ):

            stripped = lines[i].strip()

            if stripped.upper() == end_marker.upper():

                end_index = i
                break

    return lines[
        start_index:end_index
    ]


def parse_findings(lines):

    findings = []

    current = None

    in_evidence = False

    for raw_line in lines:

        line = raw_line.rstrip()

        stripped = line.strip()

        if not stripped:
            continue

        finding_match = re.match(
            r"^Finding\s+\d+",
            stripped,
            re.IGNORECASE
        )

        if finding_match:

            if current is not None:

                findings.append(
                    current
                )

            current = {
                "type": "",
                "severity": "",
                "source": "",
                "message": "",
                "evidence": []
            }

            in_evidence = False

            continue

        if current is None:
            continue

        if stripped.lower().startswith(
            "type:"
        ):

            current["type"] = (
                stripped.split(
                    ":",
                    1
                )[1].strip()
            )

            in_evidence = False

        elif stripped.lower().startswith(
            "severity:"
        ):

            current["severity"] = (
                stripped.split(
                    ":",
                    1
                )[1].strip()
            )

            in_evidence = False

        elif stripped.lower().startswith(
            "source:"
        ):

            current["source"] = (
                stripped.split(
                    ":",
                    1
                )[1].strip()
            )

            in_evidence = False

        elif stripped.lower().startswith(
            "message:"
        ):

            current["message"] = (
                stripped.split(
                    ":",
                    1
                )[1].strip()
            )

            in_evidence = False

        elif stripped.lower().startswith(
            "reason:"
        ):

            current["message"] = (
                stripped.split(
                    ":",
                    1
                )[1].strip()
            )

            in_evidence = False

        elif stripped.lower() == "evidence:":

            in_evidence = True

        elif in_evidence:

            current["evidence"].append(
                stripped
            )

    if current is not None:

        findings.append(
            current
        )

    return findings


def parse_score(
    output,
    findings
):

    match = re.search(
        r"Phishing Risk Score:\s*(\d+)\s*/\s*100",
        output,
        re.IGNORECASE
    )

    if match:

        return min(
            int(match.group(1)),
            100
        )

    high = sum(
        1
        for finding in findings
        if finding.get(
            "severity",
            ""
        ).upper() == "HIGH"
    )

    medium = sum(
        1
        for finding in findings
        if finding.get(
            "severity",
            ""
        ).upper() == "MEDIUM"
    )

    low = sum(
        1
        for finding in findings
        if finding.get(
            "severity",
            ""
        ).upper() == "LOW"
    )

    raw_score = (
        high * 25
        + medium * 10
        + low * 5
    )

    return min(
        raw_score,
        100
    )


def parse_risk(output):

    match = re.search(
        r"Overall Risk:\s*(.+)",
        output,
        re.IGNORECASE
    )

    if match:

        return match.group(
            1
        ).strip()

    return "NOT ANALYZED"


def get_counts(findings):

    high = 0
    medium = 0
    low = 0

    for finding in findings:

        severity = finding.get(
            "severity",
            ""
        ).upper()

        if severity == "HIGH":

            high += 1

        elif severity == "MEDIUM":

            medium += 1

        elif severity == "LOW":

            low += 1

    return high, medium, low


# ============================================================
# RECOMMENDATION
# ============================================================

def get_recommendation(risk):

    risk_upper = risk.upper()

    if risk_upper == "HIGH":

        return (
            "HIGH RISK: Do not trust this email. Avoid clicking links, "
            "opening attachments, replying with sensitive information, "
            "or entering credentials. Verify the sender through an "
            "independent trusted channel."
        )

    if risk_upper == "MEDIUM-HIGH":

        return (
            "MEDIUM-HIGH RISK: Treat this email with strong caution. "
            "Verify the sender and inspect links carefully before taking "
            "any action."
        )

    if risk_upper == "MEDIUM":

        return (
            "MEDIUM RISK: Some suspicious indicators were detected. "
            "Verify the sender and email content before interacting "
            "with links or attachments."
        )

    if risk_upper == "LOW-MEDIUM":

        return (
            "LOW-MEDIUM RISK: The email contains a limited suspicious "
            "indicator. Remain cautious and verify unexpected requests."
        )

    if risk_upper == "LOW":

        return (
            "LOW RISK: No significant phishing indicators were detected "
            "by the current analysis engine. Continue following normal "
            "email security practices."
        )

    return (
        "Run the analysis to receive a security recommendation."
    )


# ============================================================
# DISPLAY FINDINGS
# ============================================================

def render_findings(
    widget,
    findings,
    empty_message
):

    widget.config(
        state="normal"
    )

    widget.delete(
        "1.0",
        "end"
    )

    if not findings:

        widget.insert(
            "end",
            empty_message + "\n",
            "evidence"
        )

        widget.config(
            state="disabled"
        )

        return

    widget.insert(
        "end",
        f"Findings detected: {len(findings)}\n\n",
        "heading"
    )

    for index, finding in enumerate(
        findings,
        start=1
    ):

        severity = finding.get(
            "severity",
            "UNKNOWN"
        ).upper()

        if severity == "HIGH":

            severity_tag = "high"

        elif severity == "MEDIUM":

            severity_tag = "medium"

        elif severity == "LOW":

            severity_tag = "low"

        else:

            severity_tag = "label"

        widget.insert(
            "end",
            f"Finding {index}\n",
            "heading"
        )

        widget.insert(
            "end",
            "Type: ",
            "label"
        )

        widget.insert(
            "end",
            f"{finding.get('type', 'N/A')}\n"
        )

        widget.insert(
            "end",
            "Severity: ",
            "label"
        )

        widget.insert(
            "end",
            f"{severity}\n",
            severity_tag
        )

        widget.insert(
            "end",
            "Source: ",
            "label"
        )

        widget.insert(
            "end",
            f"{finding.get('source', 'N/A')}\n"
        )

        widget.insert(
            "end",
            "Message: ",
            "label"
        )

        widget.insert(
            "end",
            f"{finding.get('message', 'N/A')}\n"
        )

        widget.insert(
            "end",
            "Evidence:\n",
            "label"
        )

        evidence = finding.get(
            "evidence",
            []
        )

        if evidence:

            for item in evidence:

                widget.insert(
                    "end",
                    f"    {item}\n",
                    "evidence"
                )

        else:

            widget.insert(
                "end",
                "    No additional evidence available.\n",
                "evidence"
            )

        widget.insert(
            "end",
            "\n"
        )

        widget.insert(
            "end",
            "-" * 70
        )

        widget.insert(
            "end",
            "\n\n"
        )

    widget.config(
        state="disabled"
    )


# ============================================================
# FULL OUTPUT
# ============================================================

def render_full_output(output):

    full_output_text.config(
        state="normal"
    )

    full_output_text.delete(
        "1.0",
        "end"
    )

    full_output_text.insert(
        "end",
        output,
        "evidence"
    )

    full_output_text.config(
        state="disabled"
    )


# ============================================================
# SCORE BREAKDOWN
# ============================================================

def render_score_breakdown(
    high,
    medium,
    low,
    score
):

    raw_score = (
        high * 25
        + medium * 10
        + low * 5
    )

    breakdown_text.config(
        state="normal"
    )

    breakdown_text.delete(
        "1.0",
        "end"
    )

    breakdown_text.insert(
        "end",
        "PHISHING SCORE CALCULATION\n\n",
        "heading"
    )

    breakdown_text.insert(
        "end",
        "HIGH findings:   ",
        "label"
    )

    breakdown_text.insert(
        "end",
        f"{high} x 25 = {high * 25}\n"
    )

    breakdown_text.insert(
        "end",
        "MEDIUM findings: ",
        "label"
    )

    breakdown_text.insert(
        "end",
        f"{medium} x 10 = {medium * 10}\n"
    )

    breakdown_text.insert(
        "end",
        "LOW findings:    ",
        "label"
    )

    breakdown_text.insert(
        "end",
        f"{low} x 5 = {low * 5}\n\n"
    )

    breakdown_text.insert(
        "end",
        "Raw Score:       ",
        "label"
    )

    breakdown_text.insert(
        "end",
        f"{raw_score}\n"
    )

    breakdown_text.insert(
        "end",
        "Final Score:     ",
        "label"
    )

    breakdown_text.insert(
        "end",
        f"{score}/100\n",
        "heading"
    )

    if raw_score > 100:

        breakdown_text.insert(
            "end",
            "\nRaw score exceeded 100, so the final score was capped at 100.",
            "evidence"
        )

    breakdown_text.config(
        state="disabled"
    )


# ============================================================
# RISK DISPLAY
# ============================================================

def update_risk_display(risk):

    risk_upper = risk.upper()

    if risk_upper == "HIGH":

        risk_color = RED

    elif risk_upper == "MEDIUM-HIGH":

        risk_color = ORANGE

    elif risk_upper == "MEDIUM":

        risk_color = YELLOW

    elif risk_upper == "LOW-MEDIUM":

        risk_color = BLUE

    elif risk_upper == "LOW":

        risk_color = GREEN

    else:

        risk_color = MUTED

    risk_badge.config(
        text=risk,
        fg=risk_color
    )


# ============================================================
# SCORE DISPLAY
# ============================================================

def update_score_display(score):

    score_var.set(
        str(score)
    )

    score_progress["value"] = score

    if score >= 70:

        score_value_label.config(
            fg=RED
        )

    elif score >= 40:

        score_value_label.config(
            fg=ORANGE
        )

    else:

        score_value_label.config(
            fg=GREEN
        )


# ============================================================
# MAIN ANALYSIS
# ============================================================

def run_analysis():

    file_path = selected_file.get().strip()

    if not file_path:

        messagebox.showwarning(
            "No Email Selected",
            "Please select an .eml file first."
        )

        return

    if not os.path.exists(file_path):

        messagebox.showerror(
            "File Not Found",
            "The selected email file could not be found."
        )

        return

    if not os.path.exists(ANALYZER_FILE):

        messagebox.showerror(
            "Analyzer Not Found",
            f"Could not find:\n\n{ANALYZER_FILE}"
        )

        return

    analyze_button.config(
        state="disabled"
    )

    select_button.config(
        state="disabled"
    )

    status_var.set(
        "Running email security analysis..."
    )

    status_dot.config(
        fg=YELLOW
    )

    status_text.config(
        text="ANALYZING"
    )

    root.update_idletasks()

    try:

        process = subprocess.run(
            [
                sys.executable,
                ANALYZER_FILE
            ],
            input=file_path + "\n",
            text=True,
            capture_output=True,
            cwd=BASE_DIR
        )

        output = process.stdout

        if process.stderr:

            output += (
                "\n\n--- ERROR OUTPUT ---\n"
            )

            output += process.stderr

        if process.returncode != 0:

            status_var.set(
                "Analysis failed"
            )

            status_dot.config(
                fg=RED
            )

            status_text.config(
                text="ANALYSIS ERROR"
            )

            messagebox.showerror(
                "Analysis Error",
                "The analysis engine returned an error.\n\n"
                + process.stderr
            )

            return

        # ====================================================
        # GET SECTIONS
        # ====================================================

        content_lines = get_section(
            output,
            "CONTENT ANALYSIS",
            "HEADER ANALYSIS"
        )

        header_lines = get_section(
            output,
            "HEADER ANALYSIS",
            "URL ANALYSIS"
        )

        url_lines = get_section(
            output,
            "URL ANALYSIS",
            "RISK ASSESSMENT"
        )

        # ====================================================
        # PARSE FINDINGS
        # ====================================================

        content_findings = parse_findings(
            content_lines
        )

        header_findings = parse_findings(
            header_lines
        )

        url_findings = parse_findings(
            url_lines
        )

        all_findings = (
            content_findings
            + header_findings
            + url_findings
        )

        # ====================================================
        # COUNTS
        # ====================================================

        high, medium, low = get_counts(
            all_findings
        )

        total = (
            high
            + medium
            + low
        )

        high_var.set(
            str(high)
        )

        medium_var.set(
            str(medium)
        )

        low_var.set(
            str(low)
        )

        total_var.set(
            str(total)
        )

        # ====================================================
        # SCORE
        # ====================================================

        score = parse_score(
            output,
            all_findings
        )

        update_score_display(
            score
        )

        # ====================================================
        # RISK
        # ====================================================

        risk = parse_risk(
            output
        )

        risk_var.set(
            risk
        )

        update_risk_display(
            risk
        )

        # ====================================================
        # RECOMMENDATION
        # ====================================================

        recommendation = get_recommendation(
            risk
        )

        recommendation_var.set(
            recommendation
        )

        # ====================================================
        # RENDER FINDINGS
        # ====================================================

        render_findings(
            content_text,
            content_findings,
            "No suspicious content findings detected."
        )

        render_findings(
            header_text,
            header_findings,
            "No suspicious header findings detected."
        )

        render_findings(
            url_text,
            url_findings,
            "No suspicious URL findings detected."
        )

        render_full_output(
            output
        )

        render_score_breakdown(
            high,
            medium,
            low,
            score
        )

        # ====================================================
        # STATUS
        # ====================================================

        status_var.set(
            f"Analysis completed - {total} finding(s) detected"
        )

        status_dot.config(
            fg=GREEN
        )

        status_text.config(
            text="ANALYSIS COMPLETE"
        )

        canvas.yview_moveto(
            0
        )

    except Exception as e:

        status_var.set(
            "Unexpected error occurred"
        )

        status_dot.config(
            fg=RED
        )

        status_text.config(
            text="SYSTEM ERROR"
        )

        messagebox.showerror(
            "Unexpected Error",
            f"An unexpected error occurred:\n\n{e}"
        )

    finally:

        select_button.config(
            state="normal"
        )

        analyze_button.config(
            state=(
                "normal"
                if selected_file.get()
                else "disabled"
            )
        )


# ============================================================
# FINAL SETUP
# ============================================================

root.update_idletasks()

canvas.configure(
    scrollregion=canvas.bbox("all")
)

root.mainloop()