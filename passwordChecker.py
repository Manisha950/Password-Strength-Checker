"""
Strong Password Detection
=========================
Practice Project — "Automate The Boring Stuff With Python", Chapter 7, p.171
Plus assignment extension: search a known-compromised passwords list
(SecLists "10-million-password-list-top-10000.txt").

This program does two things:

  1. Uses MULTIPLE REGULAR EXPRESSIONS to verify a password is "strong":
       - at least 8 characters long
       - contains at least one uppercase letter
       - contains at least one lowercase letter
       - contains at least one digit

  2. Reads the SecLists top-10,000 most common / breached passwords
     from a local file (`common_passwords_top10000.txt`, in the same
     folder as this script) and verifies the password is NOT on that list.

     The script PREFERS the local file. If the file already exists in
     the folder, it's used directly with no network call. If the file is
     missing or empty, the script falls back to downloading it from
     GitHub on first run and caches it next to the script.

     To use a custom list: just drop your own one-password-per-line
     file at `common_passwords_top10000.txt` next to this script.

It can be run in two modes:

  GUI:  python password_checker.py
  CLI:  python password_checker.py --cli [password1 password2 ...]
        (with no passwords, prompts interactively)

Source for the common-passwords list (the upstream SecLists repo renamed
the file recently; the working URL today is the first one below — the
script tries both, plus the Kali mirror, automatically):
  https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt
  (old name, now 404 on upstream:
   https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt)
"""

# `from __future__ import annotations` makes type hints (like `list[str]`)
# evaluated as strings, so the file works on older Python versions too.
from __future__ import annotations

import os               # file path helpers (joining paths, getting file sizes)
import re               # regular expressions — the textbook tool for this job
import sys              # used to read command-line arguments (sys.argv)
import threading        # so the long download doesn't freeze the GUI
import urllib.request   # built-in HTTP client; downloads the list from GitHub


# --------------------------------------------------------------------------- #
# Config — constants used throughout the program.
# --------------------------------------------------------------------------- #

# The SecLists repo renamed "10-million-password-list-top-10000.txt" to
# "10k-most-common.txt" upstream, but Kali's mirror still publishes the
# original filename. We keep a list of candidate URLs and try each in order
# so the script keeps working regardless of which one is currently live.
PASSWORD_LIST_URLS = [
    # First choice: the renamed file on the upstream SecLists repo.
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
    # Second choice: the original filename, if upstream restored it.
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    # Third choice: Kali Linux's GitLab mirror — still uses the original name.
    "https://gitlab.com/kalilinux/packages/seclists/-/raw/kali/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
]

# Folder containing this script — used so the cache file lives next to it.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Full path to the local cache of the downloaded common-passwords file.
CACHE_FILE = os.path.join(SCRIPT_DIR, "common_passwords_top10000.txt")

# A simple regex that recognises something that "looks like" an email:
#   one or more chars that aren't @ or whitespace, then @, then more chars,
#   then a dot, then more chars. Good enough for UI feedback.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------------------------------- #
# Textbook function — uses MULTIPLE regular expressions
# (Automate The Boring Stuff With Python, Ch.7, p.171)
# --------------------------------------------------------------------------- #

# Each rule is its OWN compiled regex, exactly as the textbook recommends.
# Pre-compiling once is faster than re-compiling on every check.
# Rules 1-4 are the textbook definition (Ch.7, p.171).
# Rules 5-6 are stricter best-practice extensions added so the verdict
# matches the live UI panel (every visible rule is required to pass).
LENGTH_RE    = re.compile(r".{8,}")            # any 8 or more characters
UPPERCASE_RE = re.compile(r"[A-Z]")            # one uppercase letter anywhere
LOWERCASE_RE = re.compile(r"[a-z]")            # one lowercase letter anywhere
DIGIT_RE     = re.compile(r"\d")               # one digit (0-9) anywhere
SYMBOL_RE    = re.compile(r"[^A-Za-z0-9\s]")   # at least one symbol
SPACE_RE     = re.compile(r"\s")               # any whitespace (forbidden)


def is_strong_password(password: str) -> tuple[bool, list[str]]:
    """Return (is_strong, list_of_failure_messages).

    Strong = passes ALL SIX rules:
      1. at least 8 characters long              (textbook)
      2. contains at least one uppercase letter   (textbook)
      3. contains at least one lowercase letter   (textbook)
      4. contains at least one digit              (textbook)
      5. contains at least one symbol             (best-practice)
      6. contains no whitespace                   (best-practice)

    Each rule is its own regex pattern. Rules 5-6 extend the textbook
    spec so this verdict and the live UI rules panel stay in lock-step.
    """
    # Build a list of human-readable reasons the password fails each rule.
    failures: list[str] = []

    # Rule 1: length. `.search()` returns None if the pattern isn't found.
    if not LENGTH_RE.search(password):
        failures.append("Password must be at least 8 characters long.")
    # Rule 2: must contain at least one uppercase letter.
    if not UPPERCASE_RE.search(password):
        failures.append("Password must contain at least one uppercase letter.")
    # Rule 3: must contain at least one lowercase letter.
    if not LOWERCASE_RE.search(password):
        failures.append("Password must contain at least one lowercase letter.")
    # Rule 4: must contain at least one digit.
    if not DIGIT_RE.search(password):
        failures.append("Password must contain at least one digit.")
    # Rule 5: must contain at least one symbol (anything not a-z/A-Z/0-9).
    if not SYMBOL_RE.search(password):
        failures.append("Password must contain at least one symbol.")
    # Rule 6: must not contain spaces or any other whitespace.
    if not password or SPACE_RE.search(password):
        failures.append("Password must not contain spaces.")

    # If `failures` is empty, the password passed all six rules.
    # Returning a tuple lets the caller see both the boolean and the reasons.
    return len(failures) == 0, failures


# --------------------------------------------------------------------------- #
# Common-passwords list — download + cache + lookup
# --------------------------------------------------------------------------- #

def _cache_looks_valid() -> bool:
    """Return True if the local cache file exists and isn't empty.

    The script reads from `common_passwords_top10000.txt` in the same
    folder. If you drop your own copy of the SecLists list there (any
    size, any number of entries), the script uses it as-is and skips
    the network download entirely.
    """
    try:
        # Any non-zero file size is honored. Drop in your own list and
        # the script will use it without re-downloading.
        return os.path.getsize(CACHE_FILE) > 0
    except OSError:
        # File doesn't exist or can't be read.
        return False


def download_common_passwords(force: bool = False) -> str:
    """Use the local cache if present, otherwise download from GitHub.

    The script PREFERS a local file. If you've placed
    `common_passwords_top10000.txt` next to this script, it's used as-is
    and no network call is made. Only if the file is missing or empty
    does the script try the URLs in PASSWORD_LIST_URLS in order.

    Raises a useful error listing every URL tried if all downloads fail.
    """
    # If a local cache file exists and isn't empty (and we're not forcing
    # a re-download), use it. No network needed - just read the file.
    if os.path.exists(CACHE_FILE) and not force and _cache_looks_valid():
        return CACHE_FILE

    # Track every URL we tried and how it failed, for a useful error later.
    errors: list[str] = []

    # Walk through the candidate URLs in order. First one that works wins.
    for url in PASSWORD_LIST_URLS:
        try:
            # Some hosts reject requests without a User-Agent. Set one.
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (StrongPasswordChecker)"},
            )
            # Open the URL and read the entire body. Timeout protects us
            # from hanging forever if the network is slow.
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()

            # Guard against a "200 OK" that's actually a tiny error page.
            if len(data) < 50_000:
                errors.append(f"{url} -> file too small ({len(data)} bytes)")
                continue

            # Save the bytes to the cache file. "wb" = write, binary.
            with open(CACHE_FILE, "wb") as f:
                f.write(data)
            # Success — we're done; return the cache path.
            return CACHE_FILE
        except Exception as e:  # noqa: BLE001
            # Capture the exception type and message and try the next URL.
            errors.append(f"{url} -> {type(e).__name__}: {e}")

    # If we get here, every URL failed. Raise an exception that includes
    # all the diagnostic detail — the GUI surfaces this to the user.
    raise RuntimeError(
        "Could not download the SecLists common-passwords list from any "
        "known mirror. Attempts:\n  - " + "\n  - ".join(errors)
    )


def load_common_passwords() -> set[str]:
    """Return a set of common passwords for O(1) membership tests.

    Sets in Python are hash tables, so checking `password in common_set`
    is essentially instant regardless of how many entries there are.
    """
    # Make sure the file is cached on disk first.
    path = download_common_passwords()
    # Read the file and use a set comprehension to:
    #   - strip whitespace from each line,
    #   - drop empty lines,
    #   - deduplicate naturally (sets ignore duplicates).
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return {line.strip() for line in f if line.strip()}


def is_compromised(password: str, common_set: set[str]) -> bool:
    """True if the password appears in the common-passwords list."""
    # Membership test on a set: roughly O(1) regardless of list size.
    return password in common_set


# --------------------------------------------------------------------------- #
# Combined evaluation + extra strength heuristics for the UI
# --------------------------------------------------------------------------- #

def evaluate(password: str, common_set: set[str]) -> dict:
    """Run BOTH checks (textbook regex + breach lookup) and return a verdict."""
    # Run the textbook rules. `strong` is True only if all four pass.
    strong, failures = is_strong_password(password)
    # Look the password up in the breach corpus.
    breached = is_compromised(password, common_set)
    # Return a dict so the caller can inspect any field individually.
    return {
        "password": password,
        "is_strong": strong,
        "failures": failures,
        "is_compromised": breached,
        # Final verdict requires BOTH: passes textbook AND not compromised.
        "is_safe": strong and not breached,
    }


def check_strength_ui(password: str) -> dict:
    """Live UI scoring across SIX rules (4 textbook + 2 best-practice).

    The four textbook rules drive the SAFE/DO NOT USE verdict; the two
    bonus rules ('Contains a symbol', 'No spaces') are best-practice
    indicators that do not change the verdict but do influence the
    Weak / Medium / Strong / Very Strong rating.
    """
    # Each entry is "human-readable rule" -> bool (passed or not).
    checks = {
        # The four textbook rules:
        "At least 8 characters":    len(password) >= 8,
        "Contains uppercase (A-Z)": bool(UPPERCASE_RE.search(password)),
        "Contains lowercase (a-z)": bool(LOWERCASE_RE.search(password)),
        "Contains a digit (0-9)":   bool(DIGIT_RE.search(password)),
        # Two best-practice extras:
        "Contains a symbol":        bool(re.search(r"[^A-Za-z0-9\s]", password)),
        "No spaces":                bool(password) and " " not in password,
    }
    # Count how many rules passed (True == 1 in `sum`).
    score = sum(1 for v in checks.values() if v)

    # Six rules total. Map score to a friendly rating.
    if score <= 2:
        rating = "Weak"
    elif score <= 4:
        rating = "Medium"
    elif score == 5:
        rating = "Strong"
    else:
        rating = "Very Strong"

    return {"checks": checks, "score": score, "rating": rating}


def check_email(email: str) -> bool:
    """Return True if the email matches the loose EMAIL_RE pattern."""
    # `email or ""` guards against `None` being passed in.
    return bool(EMAIL_RE.match(email or ""))


# --------------------------------------------------------------------------- #
# CLI mode — used to capture the execution transcript for the assignment.
# --------------------------------------------------------------------------- #

def _print_report(report: dict) -> None:
    """Pretty-print the result of evaluate() for one password.

    Mirrors what the GUI shows: per-rule check marks (6 rules), the
    overall strength rating, the breach-list result, and the final verdict.
    """
    pwd = report["password"]
    # `!r` calls repr(), which adds quotes and escapes special chars.
    print(f"Password: {pwd!r}")

    # 6-rule UI panel — same heuristics the GUI shows.
    ui = check_strength_ui(pwd)
    print("  Rules:")
    for name, passed in ui["checks"].items():
        mark = "[X]" if passed else "[ ]"
        print(f"     {mark}  {name}")
    print(f"  Strength rating:           {ui['rating']}  ({ui['score']}/6 rules)")

    # Strength block (all 6 rules - drives the verdict).
    if report["is_strong"]:
        print("  Strength (6 rules):        PASS")
    else:
        print("  Strength (6 rules):        FAIL")
        # List each failed rule on its own indented line.
        for reason in report["failures"]:
            print(f"     - {reason}")

    # Common-list block
    if report["is_compromised"]:
        print("  Common-list check:         COMPROMISED - found in SecLists top-10,000")
    else:
        print("  Common-list check:         OK - not in SecLists top-10,000")

    # Final verdict line + a trailing blank line for readability.
    verdict = "SAFE TO USE" if report["is_safe"] else "DO NOT USE"
    print(f"  Verdict:                   {verdict}\n")


def cli_main(argv: list[str]) -> None:
    """Entry point for `python password_checker.py --cli ...`."""
    # Banner so the transcript is self-explanatory.
    print("Strong Password Detection - CLI mode")
    print("====================================")
    # Tell the user where the data is coming from before we open the file.
    if _cache_looks_valid():
        print(f"Loading common passwords from local file "
              f"({os.path.basename(CACHE_FILE)})...")
    else:
        print("No local file found - downloading SecLists top-10,000 from GitHub...")
    # Reads the local cache if present; otherwise downloads.
    common = load_common_passwords()
    print(f"Loaded {len(common):,} common passwords.\n")

    # If passwords were given as arguments, evaluate each and exit.
    if argv:
        for pwd in argv:
            _print_report(evaluate(pwd, common))
        return

    # Otherwise drop into an interactive prompt loop.
    print("Enter passwords to check (blank line or Ctrl-C / Ctrl-D to quit).\n")
    while True:
        try:
            pwd = input("Password> ")
        except (EOFError, KeyboardInterrupt):
            # Ctrl-D / Ctrl-C — print a newline so the shell prompt looks clean.
            print()
            return
        # Empty input — exit gracefully.
        if not pwd:
            return
        _print_report(evaluate(pwd, common))


# --------------------------------------------------------------------------- #
# GUI mode (Tkinter)
# --------------------------------------------------------------------------- #

# We DEFER the tkinter imports to inside gui_main() so that the CLI mode
# still runs on systems that don't have Tk installed (e.g. headless servers).

# Berry & Cream palette — light theme, no black backgrounds.
# Hex strings are in HTML/CSS form; Tk understands them natively.
BG       = "#FAF6F1"   # cream window background
PANEL    = "#FFFFFF"   # paper / cards on top of the cream window
FIELD    = "#F5EFE6"   # input field background (slightly warmer than BG)
FG       = "#2F2A2D"   # ink — primary text colour
MUTED    = "#6B5C5A"   # secondary / muted text
HAIRLINE = "#E5DDD2"   # subtle borders on cards & inputs
SOFT     = "#F1E8D9"   # very light highlight bg (results panel etc.)
ACCENT   = "#6D2E46"   # berry — the main accent (buttons)
ACCENT_2 = "#5A2540"   # darker berry for hover/active states
OK       = "#6B8E4E"   # sage green — "safe / pass"
WARN     = "#C9914A"   # warm tan — "warning"
BAD      = "#B34242"   # deeper red — "fail / breached"

# Map each strength rating onto the colour the bar/label should use.
RATING_COLORS = {
    "Weak":        BAD,
    "Medium":      WARN,
    "Strong":      OK,
    "Very Strong": OK,
}


def gui_main() -> None:
    """Launch the Tkinter desktop GUI."""
    # Tkinter ships with the standard Python installer on Windows/macOS.
    # Imported here (lazily) so the CLI works without it.
    import tkinter as tk
    from tkinter import ttk, messagebox

    # --- Main application class. Inherits from tk.Tk = the root window. ---
    class PasswordCheckerApp(tk.Tk):

        def __init__(self) -> None:
            # Call tk.Tk's constructor first to set up the underlying window.
            super().__init__()
            self.title("Strong Password Detection")
            self.geometry("580x680")            # initial size in pixels
            self.minsize(520, 620)              # smallest user can shrink to
            self.configure(bg=BG)               # paint the window background

            # State that persists for the lifetime of the app.
            self.common_passwords: set[str] | None = None  # filled by the bg thread
            self.load_error: str | None = None             # error msg if download fails
            self._show_password = tk.BooleanVar(value=False)  # tied to "Show" toggle

            # Build all widgets, then start the network download in the
            # background so the UI stays responsive while it runs.
            self._build_ui()
            threading.Thread(target=self._load_passwords_async, daemon=True).start()

        # ---- UI construction --------------------------------------------

        def _build_ui(self) -> None:
            """Create every widget and lay it out."""
            # ttk.Style controls the look of "themed" widgets (ttk.*).
            style = ttk.Style(self)
            try:
                # 'clam' is a built-in theme that respects our colours.
                style.theme_use("clam")
            except tk.TclError:
                pass  # If 'clam' is missing, fall back to whatever's default.

            # Set fonts and colours for each style we'll reference below.
            style.configure("TFrame", background=BG)
            style.configure("Panel.TFrame", background=PANEL)
            style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
            style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
            style.configure("Title.TLabel", background=BG, foreground=FG, font=("Segoe UI", 18, "bold"))
            style.configure("Header.TLabel", background=PANEL, foreground=FG, font=("Segoe UI", 11, "bold"))
            # The "Check Password" button uses the berry accent colour.
            style.configure(
                "Accent.TButton",
                background=ACCENT, foreground="white",
                font=("Segoe UI", 11, "bold"), padding=(14, 8), borderwidth=0,
            )
            # `style.map` applies different colours for different states
            # (here, when the button is being clicked = "active").
            style.map("Accent.TButton", background=[("active", ACCENT_2)])

            # `outer` is a padded container that holds the whole UI.
            outer = ttk.Frame(self, padding=24)
            outer.pack(fill="both", expand=True)

            # ---- Title + subtitle ----
            ttk.Label(outer, text="Strong Password Detection", style="Title.TLabel").pack(anchor="w")
            ttk.Label(
                outer,
                text="Regex-based strength check + lookup in SecLists top-10,000 breached passwords.",
                style="Muted.TLabel",
            ).pack(anchor="w", pady=(2, 16))

            # ---- Email row ----
            ttk.Label(outer, text="Email").pack(anchor="w")
            self.email_entry = tk.Entry(
                outer, font=("Segoe UI", 11), bg=FIELD, fg=FG,
                insertbackground=FG,                # cursor colour
                relief="flat",                      # no 3D border
                highlightthickness=1,               # 1px focus ring
                highlightbackground=HAIRLINE,       # ring colour normally
                highlightcolor=ACCENT,              # ring colour when focused
            )
            # `ipady=8` is the internal vertical padding (height of the field).
            self.email_entry.pack(fill="x", ipady=8, pady=(4, 12))

            # ---- Password row (entry + Show toggle) ----
            ttk.Label(outer, text="Password").pack(anchor="w")
            # Side-by-side container for the password Entry and the Show button.
            pw_row = ttk.Frame(outer)
            pw_row.pack(fill="x", pady=(4, 4))
            # `show="•"` hides the typed characters as bullets.
            self.password_entry = tk.Entry(
                pw_row, show="•", font=("Segoe UI", 11), bg=FIELD, fg=FG,
                insertbackground=FG, relief="flat", highlightthickness=1,
                highlightbackground=HAIRLINE, highlightcolor=ACCENT,
            )
            self.password_entry.pack(side="left", fill="x", expand=True, ipady=8)

            # Update the strength rules on every keystroke …
            self.password_entry.bind("<KeyRelease>", lambda _e: self._on_password_typed())
            # … and run a full check when the user presses Enter.
            self.password_entry.bind("<Return>", lambda _e: self._on_check())

            # The Show / Hide toggle next to the password field.
            tk.Checkbutton(
                pw_row, text="Show", variable=self._show_password, command=self._toggle_show,
                bg=BG, fg=MUTED, activebackground=BG, activeforeground=FG,
                selectcolor=BG, borderwidth=0, font=("Segoe UI", 9),
            ).pack(side="left", padx=(8, 0))

            # ---- Strength bar ----
            # `bar_wrap` reserves vertical space so other widgets don't shift.
            bar_wrap = tk.Frame(outer, bg=BG, height=8)
            bar_wrap.pack(fill="x", pady=(8, 4))
            # `bar_bg` is the empty (background) track of the bar.
            self.bar_bg = tk.Frame(bar_wrap, bg=HAIRLINE, height=8)
            self.bar_bg.pack(fill="x")
            # `bar_fill` sits on top of the track and grows in width as the
            # password gets stronger. Its colour also changes by rating.
            self.bar_fill = tk.Frame(self.bar_bg, bg=BAD, height=8, width=0)
            self.bar_fill.place(x=0, y=0, relheight=1)

            # Text label below the bar showing "Strength: X (n/6 rules)".
            self.rating_var = tk.StringVar(value="Enter a password to check…")
            self.rating_label = tk.Label(
                outer, textvariable=self.rating_var,
                bg=BG, fg=MUTED, font=("Segoe UI", 10, "bold"),
            )
            self.rating_label.pack(anchor="w", pady=(2, 12))

            # ---- The big "Check Password" button ----
            ttk.Button(outer, text="Check Password", style="Accent.TButton",
                       command=self._on_check).pack(fill="x")

            # ---- Results panel (a white card) ----
            panel = ttk.Frame(outer, style="Panel.TFrame", padding=16)
            panel.pack(fill="both", expand=True, pady=(16, 0))

            # Section header inside the card.
            ttk.Label(panel, text="Results", style="Header.TLabel").pack(anchor="w", pady=(0, 8))

            # Email line — text gets filled in when the user clicks Check.
            self.email_result = tk.Label(panel, text="", bg=PANEL, fg=MUTED,
                                         font=("Segoe UI", 10), anchor="w", justify="left")
            self.email_result.pack(fill="x", pady=(0, 6))

            # Verdict block — multi-line, holds the SAFE / DO NOT USE message
            # and the per-rule feedback.
            self.verdict_result = tk.Label(panel, text="", bg=PANEL, fg=MUTED,
                                           font=("Segoe UI", 10, "bold"),
                                           anchor="w", justify="left", wraplength=480)
            self.verdict_result.pack(fill="x", pady=(0, 10))

            # Strength rules section header + the dynamic checklist below.
            ttk.Label(panel, text="Strength rules", style="Header.TLabel").pack(anchor="w")
            self.checks_frame = tk.Frame(panel, bg=PANEL)
            self.checks_frame.pack(fill="x", pady=(6, 0))
            # Render the checklist once with an empty password so it appears
            # immediately (all rules unchecked).
            self._render_checks(check_strength_ui(""))

            # ---- Status bar at the bottom of the window ----
            self.status_var = tk.StringVar(value="Preparing common passwords list…")
            tk.Label(self, textvariable=self.status_var, bg=BG, fg=MUTED,
                     font=("Segoe UI", 9), anchor="w", padx=24, pady=8).pack(fill="x", side="bottom")

        # ---- Small UI helpers ------------------------------------------

        def _toggle_show(self) -> None:
            """Show or hide the typed password depending on the toggle."""
            # Empty string = display chars as-is; "•" = mask them.
            self.password_entry.configure(show="" if self._show_password.get() else "•")

        def _render_checks(self, result: dict) -> None:
            """Redraw the rule checklist inside the white card."""
            # Clear any rows from the previous keystroke so we don't pile up.
            for child in self.checks_frame.winfo_children():
                child.destroy()
            # Build one row per rule.
            for name, passed in result["checks"].items():
                row = tk.Frame(self.checks_frame, bg=PANEL)
                row.pack(fill="x", pady=2)
                # Left: a tick (✓) if passed, a bullet (•) otherwise.
                tk.Label(row, text=("✓" if passed else "•"),
                         bg=PANEL, fg=(OK if passed else MUTED),
                         font=("Segoe UI", 11, "bold"), width=2).pack(side="left")
                # Right: the human-readable rule label.
                tk.Label(row, text=name, bg=PANEL,
                         fg=(FG if passed else MUTED),
                         font=("Segoe UI", 10)).pack(side="left")

        def _update_strength_bar(self, result: dict) -> None:
            """Resize and recolour the strength bar based on the score."""
            # Pick a colour for the bar fill from the rating.
            self.bar_fill.configure(bg=RATING_COLORS.get(result["rating"], BAD))
            # We need to know the bar's actual pixel width to compute the
            # fill width — `update_idletasks` flushes any pending layout work.
            self.bar_bg.update_idletasks()
            # Bar's full width in pixels (avoid divide-by-zero with max(.,1)).
            total = max(self.bar_bg.winfo_width(), 1)
            # Fill width proportional to how many of the 6 rules passed.
            self.bar_fill.configure(width=int(total * (result["score"] / 6)))
            # Update the text label below the bar.
            self.rating_var.set(f"Strength: {result['rating']}  ({result['score']}/6 rules)")
            # Match the label colour to the rating colour for emphasis.
            self.rating_label.configure(fg=RATING_COLORS.get(result["rating"], MUTED))

        # ---- Background work --------------------------------------------

        def _load_passwords_async(self) -> None:
            """Runs in a daemon thread; loads the breach list from disk
            (or downloads it from GitHub if no local file is present)."""
            try:
                # If the local cache file already has content, skip the
                # network entirely. Otherwise we need to download.
                using_local = _cache_looks_valid()
                if using_local:
                    self.status_var.set(
                        f"Loading common passwords from {os.path.basename(CACHE_FILE)}…"
                    )
                else:
                    self.status_var.set(
                        "Local file missing - downloading top-10,000 common passwords from GitHub…"
                    )
                # This call blocks until the file is loaded - but we're on
                # a background thread so the GUI remains responsive.
                self.common_passwords = load_common_passwords()
                source = "local file" if using_local else "GitHub download"
                self.status_var.set(
                    f"Loaded {len(self.common_passwords):,} common passwords "
                    f"from {source} ({os.path.basename(CACHE_FILE)})."
                )
            except Exception as e:  # noqa: BLE001
                # Stash the full error message - it lists every URL attempted
                # and the exact failure for each, which makes diagnosis easy.
                self.load_error = str(e)
                self.status_var.set(
                    "Could not load common passwords (check internet / proxy). "
                    "Click Check Password for details."
                )

        # ---- Event handlers ---------------------------------------------

        def _on_password_typed(self) -> None:
            """Called on every keystroke in the password field."""
            r = check_strength_ui(self.password_entry.get())
            # Update the rule rows AND the bar to match.
            self._render_checks(r)
            self._update_strength_bar(r)

        def _on_check(self) -> None:
            """Called when the user clicks Check Password (or hits Enter)."""
            # Pull whatever the user has typed right now.
            email = self.email_entry.get().strip()
            password = self.password_entry.get()

            # ---- Email feedback ----
            if not email:
                self.email_result.configure(text="Email: (not provided)", fg=MUTED)
            elif check_email(email):
                self.email_result.configure(text=f"Email: {email}  ✓ valid format", fg=OK)
            else:
                self.email_result.configure(text=f"Email: {email}  ✗ invalid format", fg=BAD)

            # If the user clicked Check with no password, prompt and exit.
            if not password:
                self.verdict_result.configure(text="Please enter a password.", fg=WARN)
                return

            # Refresh the live strength panel (in case Check was clicked
            # before the user typed in the field).
            r_ui = check_strength_ui(password)
            self._render_checks(r_ui)
            self._update_strength_bar(r_ui)

            # ---- Handle the case where the breach list is unavailable ----
            if self.common_passwords is None:
                if self.load_error:
                    # The download failed earlier — surface the full error.
                    self.verdict_result.configure(
                        text=(
                            "✗ Could not download the SecLists common-passwords "
                            "list. The compromised-password check is unavailable.\n\n"
                            f"Details: {self.load_error}"
                        ),
                        fg=BAD,
                    )
                else:
                    # The download is still in flight; tell the user to wait.
                    self.verdict_result.configure(
                        text="Common-passwords list still loading — try again in a moment.",
                        fg=WARN,
                    )
                return

            # ---- Both checks: textbook regex + breach lookup ----
            report = evaluate(password, self.common_passwords)

            # Build the verdict block line by line.
            lines: list[str] = []
            if report["is_strong"]:
                lines.append("✓ Meets all six strength rules.")
            else:
                lines.append("✗ Fails strength rules:")
                for f in report["failures"]:
                    lines.append(f"   • {f}")
            if report["is_compromised"]:
                lines.append("✗ FOUND in SecLists top-10,000 — do NOT use.")
            else:
                lines.append("✓ Not in SecLists top-10,000.")
            lines.append("")  # blank line before the verdict
            lines.append("Verdict: " + ("SAFE TO USE" if report["is_safe"] else "DO NOT USE"))

            # Pick a colour for the whole verdict block.
            color = OK if report["is_safe"] else BAD
            # Join the lines with newlines — Tk's Label honours \n in `text`.
            self.verdict_result.configure(text="\n".join(lines), fg=color)

            # If the password matched the breach list, also pop a warning
            # dialog — hard to ignore.
            if report["is_compromised"]:
                messagebox.showwarning(
                    "Compromised password",
                    "This password appears in the SecLists top-10,000 most common / "
                    "breached passwords. Choose something else.",
                )

    # `mainloop()` blocks until the user closes the window, handling
    # all UI events (clicks, keystrokes, redraws) along the way.
    PasswordCheckerApp().mainloop()


# --------------------------------------------------------------------------- #
# Entry point — chooses CLI vs GUI based on arguments.
# --------------------------------------------------------------------------- #

def main() -> None:
    """Top-level dispatcher: GUI by default, CLI if --cli is the first arg."""
    # `sys.argv[0]` is the script's own filename; the rest are user args.
    args = sys.argv[1:]
    if args and args[0] in ("--cli", "-c"):
        # Pass the rest of the args through (passwords to check).
        cli_main(args[1:])
    else:
        gui_main()


# This idiom ensures `main()` runs only when the file is executed directly,
# not when it's imported as a module from another script.
if __name__ == "__main__":
    main()