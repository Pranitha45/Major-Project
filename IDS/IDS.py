import warnings
warnings.filterwarnings("ignore")
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['PYTHONWARNINGS'] = 'ignore'

import logging
logging.getLogger('tensorflow').setLevel(logging.ERROR)
logging.getLogger('keras').setLevel(logging.ERROR)
logging.disable(logging.WARNING)

import sys
if not sys.warnoptions:
    warnings.simplefilter("ignore")

# ── Standard 
import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np
import pandas as pd
import socket, time, math

# ── Graphics 
from PIL import Image, ImageDraw, ImageTk
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt

# ── ML 
from sklearn import svm
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import (train_test_split, cross_val_score,
                                     StratifiedKFold)
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (accuracy_score, confusion_matrix,
                              classification_report)
from keras.models import Sequential
from keras.layers import Dense
import keras.callbacks as kc
from sklearn_extensions.extreme_learning_machines.elm import GenELMClassifier
from sklearn_extensions.extreme_learning_machines.random_layer import MLPRandomLayer


filename       = None
data           = None
X = Y = X_train = X_test = y_train = y_test = None
svm_acc        = 0.0
random_acc     = 0.0
dnn_acc        = 0.0
elm_acc        = 0.0
normal_time    = 0.0
parallel_time  = 0.0
scaler         = None

le_proto       = LabelEncoder()
le_service     = LabelEncoder()
le_flag        = LabelEncoder()
le_fitted      = False


LABEL_MAP = {
    'normal':0,'neptune':1,'warezclient':2,'ipsweep':3,'portsweep':4,
    'teardrop':5,'nmap':6,'satan':7,'smurf':8,'pod':9,'back':10,
    'guess_passwd':11,'ftp_write':12,'multihop':13,'rootkit':14,
    'buffer_overflow':15,'imap':16,'warezmaster':17
}
REVERSE_MAP = {v: k for k, v in LABEL_MAP.items()}


BG        = "#07111f"
PANEL     = "#0d1f35"
ACCENT    = "#00e5ff"
ACCENT2   = "#00ff99"
WARN_COL  = "#ff4f4f"
TEXT_FG   = "#c8e6ff"
DIM       = "#1e3550"
BTN_BG    = "#0a2540"
BTN_HOV   = "#0f3a60"
CARD_BG   = "#0b1e33"


root = tk.Tk()
root.title("Anomaly Detection in Network Traffic")
root.geometry("1380x880")
root.resizable(True, True)
root.configure(bg=BG)

def make_banner(w=1380, h=88):
    img  = Image.new("RGB", (w, h), "#07111f")
    draw = ImageDraw.Draw(img)
    for x in range(w):
        r = int(0x07 + (0x00 - 0x07) * x / w)
        g = int(0x11 + (0x29 - 0x11) * x / w)
        b = int(0x1f + (0x55 - 0x1f) * x / w)
        draw.line([(x, 0), (x, h)], fill=(r, g, b))
    draw.rectangle([0, h-3, w, h], fill="#00e5ff")   # cyan bottom line
    return ImageTk.PhotoImage(img)

banner_img = make_banner()

banner_cv = tk.Canvas(root, width=1380, height=88,
                       bg="#07111f", highlightthickness=0)
banner_cv.place(x=0, y=0)
banner_cv.create_image(0, 0, anchor="nw", image=banner_img)
banner_cv.create_text(690, 32,
    text="⬡  ANOMALY DETECTION IN NETWORK TRAFFIC",
    font=("Courier New", 22, "bold"), fill=ACCENT, anchor="center")
banner_cv.create_text(690, 62,
    text="NSL-KDD Dataset  |  SVM  ·  Random Forest  ·  DNN  ·  ELM  |  Intrusion Detection System",
    font=("Courier New", 10), fill="#4a7fa0", anchor="center")


hex_cv = tk.Canvas(root, bg=BG, highlightthickness=0)
hex_cv.place(x=0, y=88, relwidth=1, relheight=1)

def hex_pts(cx, cy, size):
    pts = []
    for i in range(6):
        a = math.pi/3*i - math.pi/6
        pts += [cx + size*math.cos(a), cy + size*math.sin(a)]
    return pts

def build_hex_grid():
    hex_cv.delete("hex")
    w = root.winfo_width()  or 1380
    h = root.winfo_height() or 880
    S  = 26
    dx = S * math.sqrt(3)
    dy = S * 1.5
    fills = ["#081522", "#070f1a"]
    for row in range(int((h-88)/dy)+2):
        for col in range(int(w/dx)+2):
            cx   = col*dx + (dx/2 if row%2 else 0)
            cy   = row*dy
            pts  = hex_pts(cx, cy, S-2)
            fill = fills[(row + col) % 2]
            hex_cv.create_polygon(pts, fill=fill, outline=DIM,
                                  width=1, tags="hex")

root.after(200, build_hex_grid)


SB_W  = 252
sb_cv = tk.Canvas(root, width=SB_W, bg=PANEL,
                   highlightthickness=1, highlightbackground=DIM)
sb_cv.place(x=8, y=96, height=772)
sb_cv.create_line(0, 0, SB_W, 0, fill=ACCENT, width=2)

def sb_section(y, lbl):
    sb_cv.create_text(14, y, text=lbl, anchor="w",
        font=("Courier New", 8, "bold"), fill="#2a5070")
    sb_cv.create_line(14, y+13, SB_W-14, y+13, fill="#152840")

sb_section(12,  "▸ DATA")
sb_section(172, "▸ ALGORITHMS")
sb_section(408, "▸ ANALYSIS")

# ── Sidebar button class ──────────────────────────────────────────
class SbBtn:
    def __init__(self, cv, y, label, cmd, color=ACCENT):
        self.cv   = cv
        self.cmd  = cmd
        self.col  = color
        H = 34
        x1, x2 = 12, SB_W-12
        self.r = cv.create_rectangle(x1, y, x2, y+H,
                     fill=BTN_BG, outline=color, width=1)
        self.t = cv.create_text(x1+10, y+H//2, text=label,
                     anchor="w", font=("Courier New", 9, "bold"), fill=color)
        for tag in (self.r, self.t):
            cv.tag_bind(tag, "<Enter>",    self._enter)
            cv.tag_bind(tag, "<Leave>",    self._leave)
            cv.tag_bind(tag, "<Button-1>", self._click)

    def _enter(self, _):
        self.cv.itemconfig(self.r, fill=BTN_HOV)
        self.cv.itemconfig(self.t, fill="#ffffff")

    def _leave(self, _):
        self.cv.itemconfig(self.r, fill=BTN_BG)
        self.cv.itemconfig(self.t, fill=self.col)

    def _click(self, _):
        self.cmd()

# DATA buttons
SbBtn(sb_cv,  30,  "▲  Upload Dataset",           lambda: cb_upload())
SbBtn(sb_cv,  72,  "⚙  Preprocess Dataset",        lambda: cb_preprocess())
SbBtn(sb_cv, 114,  "⬡  Generate Training Model",   lambda: cb_generate_model())

# ALGORITHM buttons
SbBtn(sb_cv, 190,  "⟳  Run SVM",                   lambda: cb_run_svm(),    ACCENT2)
SbBtn(sb_cv, 232,  "⟳  Run Random Forest",         lambda: cb_run_rf(),     ACCENT2)
SbBtn(sb_cv, 274,  "⟳  Run DNN",                   lambda: cb_run_dnn(),    ACCENT2)
SbBtn(sb_cv, 316,  "⟳  Run ELM",                   lambda: cb_run_elm(),    ACCENT2)
SbBtn(sb_cv, 358,  "◈  Predict Test Data",          lambda: cb_predict(),    "#ffcc00")

# ANALYSIS buttons
SbBtn(sb_cv, 426,  "▣  Accuracy Graph",             lambda: cb_acc_graph(),  "#ff6b35")
SbBtn(sb_cv, 468,  "▣  Run Parallel Processing",    lambda: cb_parallel(),   "#bf5fff")
SbBtn(sb_cv, 510,  "▣  Parallel Time Graph",        lambda: cb_time_graph(), "#bf5fff")

# File label
sb_cv.create_text(14, 572, text="LOADED FILE:", anchor="w",
    font=("Courier New", 8), fill="#2a5070")
path_var = tk.StringVar(value="None")
tk.Label(sb_cv, textvariable=path_var, bg=PANEL, fg="#4a8aaa",
    font=("Courier New", 7), wraplength=228, justify="left"
).place(x=12, y=586)

# Status
status_var = tk.StringVar(value="● READY")
status_lbl = tk.Label(sb_cv, textvariable=status_var,
    bg=PANEL, fg=ACCENT2, font=("Courier New", 9, "bold"))
status_lbl.place(x=12, y=740)

def set_status(msg, color=ACCENT2):
    status_var.set(msg)
    status_lbl.config(fg=color)
    root.update_idletasks()


card_host = tk.Frame(root, bg=BG)
card_host.place(x=270, y=96, width=1102, height=68)
_card_vars = {}

for i, (lbl, key, col) in enumerate([
    ("SVM",  "svm", "#1f77b4"),
    ("RF",   "rf",  "#2ca02c"),
    ("DNN",  "dnn", "#ff7f0e"),
    ("ELM",  "elm", "#9467bd"),
]):
    f = tk.Frame(card_host, bg=CARD_BG,
                 highlightbackground=col, highlightthickness=1)
    f.place(x=i*274, y=0, width=268, height=66)
    tk.Label(f, text=lbl, bg=CARD_BG, fg=col,
             font=("Courier New", 9, "bold")).place(x=10, y=5)
    v = tk.StringVar(value="—")
    _card_vars[key] = v
    tk.Label(f, textvariable=v, bg=CARD_BG, fg="white",
             font=("Courier New", 18, "bold")).place(x=10, y=26)
    tk.Label(f, text="accuracy", bg=CARD_BG, fg="#2a5070",
             font=("Courier New", 8)).place(x=10, y=50)

def update_card(key, val):
    _card_vars[key].set(f"{val:.2f}%")


term_outer = tk.Frame(root, bg=ACCENT, bd=1)
term_outer.place(x=270, y=170, width=1102, height=690)

top_bar = tk.Frame(term_outer, bg="#030a14", height=22)
top_bar.pack(fill="x")
tk.Label(top_bar, text="● ● ●", bg="#030a14",
         fg="#1a3a5e", font=("Courier New", 9)).pack(side="left", padx=8)
tk.Label(top_bar, text="OUTPUT TERMINAL", bg="#030a14",
         fg="#2a5070", font=("Courier New", 8, "bold")).pack(side="left")

t_frame = tk.Frame(term_outer, bg="#030a14")
t_frame.pack(fill="both", expand=True)

text = tk.Text(t_frame, bg="#030a14", fg=TEXT_FG,
               font=("Courier New", 10), relief="flat",
               insertbackground=ACCENT, wrap="word",
               selectbackground="#1a3a6e", padx=12, pady=8)
scr = tk.Scrollbar(t_frame, orient="vertical",
                    command=text.yview, bg=PANEL)
text.configure(yscrollcommand=scr.set)
scr.pack(side="right", fill="y")
text.pack(fill="both", expand=True)

text.tag_config("cyan",   foreground=ACCENT)
text.tag_config("green",  foreground=ACCENT2)
text.tag_config("red",    foreground=WARN_COL)
text.tag_config("yellow", foreground="#ffcc00")
text.tag_config("dim",    foreground="#2a5070")
text.tag_config("bold",   font=("Courier New", 10, "bold"))
text.tag_config("white",  foreground="#ffffff")

def log(msg, tag=None):
    text.insert("end", msg, tag or ())
    text.see("end")
    root.update_idletasks()

def clear_log():
    text.delete("1.0", "end")

def encode_df(df, fit=False):
    """Encode protocol_type / service / flag with LabelEncoder."""
    pairs = [('protocol_type', le_proto),
             ('service',       le_service),
             ('flag',          le_flag)]
    for col, le in pairs:
        if col not in df.columns:
            continue
        if fit:
            df[col] = le.fit_transform(df[col].astype(str))
        else:
            df[col] = df[col].astype(str).apply(
                lambda x: int(le.transform([x])[0])
                          if x in le.classes_ else 0)
    return df

def fix_numeric(df):
    """Coerce all columns to float, replacing bad values (e.g. '1e') with 0."""
    for col in df.columns:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)
    return df

def cb_upload():
    global filename
    clear_log()
    f = filedialog.askopenfilename(
        initialdir=".",
        filetypes=[("Text/CSV","*.txt *.csv"),("All","*.*")])
    if f:
        filename = f
        path_var.set(f.split("/")[-1])
        log("▲  Dataset loaded\n", "cyan")
        log(f"   {f}\n\n")
        set_status("● FILE LOADED")
    else:
        log("Upload cancelled.\n", "dim")


def _safe_read_csv(path, **kwargs):
    """pandas <1.3 uses error_bad_lines, >=1.3 uses on_bad_lines."""
    try:
        return pd.read_csv(path, on_bad_lines='skip', **kwargs)
    except TypeError:
        return pd.read_csv(path, error_bad_lines=False, warn_bad_lines=False, **kwargs)

def cb_preprocess():
    global le_fitted
    if not filename:
        messagebox.showwarning("Warning","Upload a dataset first."); return
    clear_log()
    set_status("⚙ PREPROCESSING…", "#ffcc00")
    log("⚙  Preprocessing — please wait…\n\n", "yellow")
    try:
        df = _safe_read_csv(filename)

        # 1. Encode categorical columns (fit encoders for later reuse)
        df = encode_df(df, fit=True)
        le_fitted = True

        # 2. Map label → integer
        if 'label' in df.columns:
            df['label'] = (df['label'].str.strip()
                            .map(LABEL_MAP).fillna(-1).astype(int))
            df = df[df['label'] != -1]

        # 3. Drop classes with < 5 samples
        counts = df['label'].value_counts()
        df = df[df['label'].isin(counts[counts >= 5].index)]

        # 4. Fix any typo values (e.g. '1e')
        df = fix_numeric(df)

        # 5. Keep only numeric columns
        df = df.select_dtypes(include=[np.number])

        df.to_csv("clean.txt", index=False)

        log("✔  Saved to clean.txt\n\n", "green")
        log(f"   Shape    : {df.shape}\n")
        log(f"   Features : {df.shape[1]-1}\n")
        log(f"   Samples  : {len(df)}\n\n")
        log("   Label distribution:\n", "dim")
        for lbl, cnt in df['label'].value_counts().items():
            name = REVERSE_MAP.get(int(lbl), str(lbl))
            bar  = "█" * max(1, int(cnt/80))
            log(f"   {name:<22} {bar} {cnt}\n")
        log("\n")
        set_status("● PREPROCESSED", ACCENT2)
    except Exception as e:
        log(f"ERROR: {e}\n", "red"); set_status("● ERROR", WARN_COL)


def cb_generate_model():
    global data, X, Y, X_train, X_test, y_train, y_test, scaler
    clear_log()
    set_status("⚙ LOADING MODEL…", "#ffcc00")
    log("⬡  Generating training model…\n\n", "cyan")
    try:
        data = pd.read_csv("clean.txt")

        vals    = data.values.astype(float)
        X_all   = vals[:, :-1]
        Y_all   = vals[:, -1].astype(int)

        X_train, X_test, y_train, y_test = train_test_split(
            X_all, Y_all, test_size=0.2, random_state=0)

        # StandardScaler — same as your code
        scaler  = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test  = scaler.transform(X_test)

        X, Y = X_all, Y_all

        log("✔  Model ready\n\n", "green")
        log(f"   Total    : {len(Y_all)}\n")
        log(f"   Train    : {len(y_train)}\n")
        log(f"   Test     : {len(y_test)}\n")
        log(f"   Features : {X_train.shape[1]}\n\n")
        set_status("● MODEL READY", ACCENT2)
    except Exception as e:
        log(f"ERROR: {e}\n", "red"); set_status("● ERROR", WARN_COL)


def _check_model(name="this step"):
    if X_train is None:
        messagebox.showwarning("Warning",
            f"Generate the Training Model before {name}.")
        return False
    return True

def _show_result(title, y_pred, train_acc, test_acc):
    gap = train_acc - test_acc
    log(f"\n{'─'*50}\n", "dim")
    log(f"  {title}\n", "bold")
    log(f"  Train Accuracy : ", "dim"); log(f"{train_acc:.4f}%\n", "white")
    log(f"  Test  Accuracy : ", "dim"); log(f"{test_acc:.4f}%\n", "cyan")
    log(f"  Overfit Gap    : ", "dim")
    log(f"{gap:.4f}%  ", "green" if gap < 5 else "red")
    log("✔ No overfit\n" if gap < 5 else "⚠ Possible overfit\n",
        "green" if gap < 5 else "red")
    log(f"\n  Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}\n\n")
    try:
        report = classification_report(y_test, y_pred, zero_division=0)
    except TypeError:
        report = classification_report(y_test, y_pred)
    log(f"  Classification Report:\n{report}\n")

# ── SVM
def cb_run_svm():
    global svm_acc
    if not _check_model("SVM"): return
    clear_log()
    set_status("⟳ SVM…", "#ffcc00")
    log("⟳  Training SVM (C=10, rbf, gamma=auto)…\n", "green")
    print("\n" + "="*50)
    print("  [ SVM ] Support Vector Machine")
    print("="*50)
    print("  Status : INITIALIZING  (C=10, kernel=rbf, gamma=auto)")
    try:
        cls = svm.SVC(C=10.0, gamma='auto', kernel='rbf', random_state=42)
        print("  Status : TRAINING      (fitting on training data...)")
        cls.fit(X_train, y_train)
        print("  Status : EVALUATING    (predicting on test data...)")
        y_pred    = cls.predict(X_test)
        train_acc = accuracy_score(y_train, cls.predict(X_train)) * 100
        test_acc  = accuracy_score(y_test,  y_pred) * 100
        svm_acc   = test_acc
        print("  Status : COMPLETE ✔")
        print(f"  Train Accuracy : {train_acc:.4f}%")
        print(f"  Test  Accuracy : {test_acc:.4f}%")
        print("="*50)
        update_card("svm", test_acc)
        _show_result("SVM", y_pred, train_acc, test_acc)
        set_status(f"● SVM {test_acc:.2f}%", ACCENT2)
    except Exception as e:
        print(f"  Status : FAILED ✘  {e}")
        print("="*50)
        log(f"ERROR: {e}\n", "red"); set_status("● ERROR", WARN_COL)


# ── Random Forest
def cb_run_rf():
    global random_acc
    if not _check_model("Random Forest"): return
    clear_log()
    set_status("⟳ RF…", "#ffcc00")
    log("⟳  Training Random Forest (100 trees, max_depth=None)…\n", "green")
    print("\n" + "="*50)
    print("  [ RF ] Random Forest")
    print("="*50)
    print("  Status : INITIALIZING  (100 trees, max_depth=None)")
    try:
        cls = RandomForestClassifier(n_estimators=100,
                                     max_depth=None,
                                     random_state=42, n_jobs=1)
        print("  Status : TRAINING      (fitting on training data...)")
        cls.fit(X_train, y_train)
        print("  Status : EVALUATING    (predicting on test data...)")
        y_pred    = cls.predict(X_test)
        train_acc = accuracy_score(y_train, cls.predict(X_train)) * 100
        test_acc  = accuracy_score(y_test,  y_pred) * 100
        random_acc = test_acc
        print("  Status : COMPLETE ✔")
        print(f"  Train Accuracy : {train_acc:.4f}%")
        print(f"  Test  Accuracy : {test_acc:.4f}%")
        print("  Status : CROSS-VALIDATING  (5-Fold CV...)")
        from sklearn.pipeline import Pipeline
        pipe = Pipeline([('sc', StandardScaler()),
                         ('clf', RandomForestClassifier(
                             n_estimators=100, max_depth=None,
                             random_state=42, n_jobs=1))])
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv  = cross_val_score(pipe, X, Y, cv=skf, scoring='accuracy', n_jobs=1)
        print(f"  CV Mean        : {cv.mean()*100:.4f}%")
        print(f"  CV Std         : {cv.std()*100:.4f}%")
        print("="*50)
        update_card("rf", test_acc)
        _show_result("Random Forest", y_pred, train_acc, test_acc)
        log(f"\n  5-Fold CV Scores : {[round(s*100,2) for s in cv]}\n")
        log(f"  CV Mean          : {cv.mean()*100:.4f}%\n")
        log(f"  CV Std           : {cv.std()*100:.4f}%  "
            f"({'Stable ✔' if cv.std() < 0.01 else 'Check stability'})\n\n")
        feats = data.columns.tolist()[:-1]
        top5  = sorted(zip(feats, cls.feature_importances_),
                       key=lambda x: -x[1])[:5]
        log("  Top-5 Important Features:\n", "dim")
        for fname, imp in top5:
            log(f"    {fname:<42} {imp*100:.2f}%\n")
        log("\n")
        set_status(f"● RF {test_acc:.2f}%", ACCENT2)
    except Exception as e:
        print(f"  Status : FAILED ✘  {e}")
        print("="*50)
        log(f"ERROR: {e}\n", "red"); set_status("● ERROR", WARN_COL)


# ── DNN Keras callback — prints epoch progress to terminal only
class _TerminalLogger(kc.Callback):
    TOTAL = 50
    def on_train_begin(self, logs=None):
        print("\n" + "="*50)
        print("  [ DNN ] Deep Neural Network")
        print("="*50)
        print("  Status : TRAINING      (50 epochs, batch=32)")
        print(f"  {'Epoch':<10} {'Loss':<14} {'Accuracy'}")
        print("  " + "-"*36)
    def on_epoch_end(self, epoch, logs=None):
        logs = logs or {}
        ep   = epoch + 1
        loss = logs.get('loss', 0.0)
        acc  = logs.get('accuracy', logs.get('acc', 0.0)) * 100
        print(f"  Epoch {ep:>3}/{self.TOTAL}   loss={loss:.4f}   acc={acc:.2f}%")
    def on_train_end(self, logs=None):
        print("  " + "-"*36)
        print("  Status : EVALUATING    (computing final accuracy...)")


# ── DNN
def cb_run_dnn():
    global dnn_acc
    if not _check_model("DNN"): return
    clear_log()
    set_status("⟳ DNN…", "#ffcc00")
    log("⟳  Training Deep Neural Network…\n", "green")
    try:
        n_feat    = X_train.shape[1]
        n_classes = len(np.unique(y_train))
        model = Sequential([
            Dense(64,        input_dim=n_feat, activation='relu'),
            Dense(32,        activation='relu'),
            Dense(n_classes, activation='softmax'),
        ])
        model.compile(loss='sparse_categorical_crossentropy',
                      optimizer='adam', metrics=['accuracy'])
        model.fit(X_train, y_train,
                  epochs=50, batch_size=32, verbose=0,
                  callbacks=[_TerminalLogger()])
        _, tr_acc = model.evaluate(X_train, y_train, verbose=0)
        _, te_acc = model.evaluate(X_test,  y_test,  verbose=0)
        tr_acc *= 100; te_acc *= 100
        dnn_acc = te_acc
        update_card("dnn", te_acc)
        gap = tr_acc - te_acc
        print("  Status : COMPLETE ✔")
        print(f"  Train Accuracy : {tr_acc:.4f}%")
        print(f"  Test  Accuracy : {te_acc:.4f}%")
        print("="*50)
        log(f"\n  Train Accuracy : {tr_acc:.4f}%\n")
        log(f"  Test  Accuracy : ", "dim"); log(f"{te_acc:.4f}%\n", "cyan")
        log(f"  Overfit Gap    : {gap:.4f}%\n",
            "green" if gap < 5 else "red")
        log("\n")
        set_status(f"● DNN {te_acc:.2f}%", ACCENT2)
    except Exception as e:
        print(f"  Status : FAILED ✘  {e}")
        print("="*50)
        log(f"ERROR: {e}\n", "red"); set_status("● ERROR", WARN_COL)


# ── ELM
def cb_run_elm():
    global elm_acc, normal_time
    if not _check_model("ELM"): return
    clear_log()
    set_status("⟳ ELM…", "#ffcc00")
    log("⟳  Training Extreme Learning Machine (n_hidden=100)…\n", "green")
    print("\n" + "="*50)
    print("  [ ELM ] Extreme Learning Machine")
    print("="*50)
    print("  Status : INITIALIZING  (n_hidden=100, activation=tanh)")
    try:
        start = time.time()
        cls   = GenELMClassifier(
                    hidden_layer=MLPRandomLayer(
                        n_hidden=100, activation_func='tanh',
                        random_state=0))
        print("  Status : TRAINING      (fitting on training data...)")
        cls.fit(X_train, y_train)
        print("  Status : EVALUATING    (predicting on test data...)")
        y_pred    = cls.predict(X_test)
        train_acc = accuracy_score(y_train, cls.predict(X_train)) * 100
        test_acc  = accuracy_score(y_test,  y_pred) * 100
        elapsed   = time.time() - start
        elm_acc     = test_acc
        normal_time = elapsed
        print("  Status : COMPLETE ✔")
        print(f"  Train Accuracy : {train_acc:.4f}%")
        print(f"  Test  Accuracy : {test_acc:.4f}%")
        print(f"  Execution Time : {elapsed:.4f}s")
        print("="*50)
        update_card("elm", test_acc)
        _show_result("ELM", y_pred, train_acc, test_acc)
        log(f"  Execution Time : {elapsed:.4f}s\n\n")
        set_status(f"● ELM {test_acc:.2f}%", ACCENT2)
    except Exception as e:
        print(f"  Status : FAILED ✘  {e}")
        print("="*50)
        log(f"ERROR: {e}\n", "red"); set_status("● ERROR", WARN_COL)

# ── Predict Test Data 
def cb_predict():
    global le_fitted
    if not _check_model("Predict"): return
    if not le_fitted:
        messagebox.showwarning("Warning",
            "Run Preprocess first so encoders are fitted."); return

    f = filedialog.askopenfilename(
        initialdir=".",
        filetypes=[("Text/CSV","*.txt *.csv"),("All","*.*")])
    if not f: return

    clear_log()
    set_status("⟳ PREDICTING…","#ffcc00")
    log(f"◈  Predicting: {f.split('/')[-1]}\n\n","yellow")
    try:
        df = pd.read_csv(f)
        df = encode_df(df, fit=False)       # use fitted encoders
        df = fix_numeric(df)               # fix typos like '1e'
        df = df.select_dtypes(include=[np.number])

        n_need = X_train.shape[1]
        # Pad if 1-2 cols short (e.g. test file missing last col)
        while df.shape[1] < n_need:
            df[f"_pad_{df.shape[1]}"] = 0.0

        features = df.iloc[:, :n_need].values.astype(float)
        features = scaler.transform(features)   # scale same as training

        # Retrain ELM for prediction
        cls = GenELMClassifier(
                  hidden_layer=MLPRandomLayer(
                      n_hidden=100, activation_func='tanh'))
        cls.fit(X_train, y_train)
        preds = cls.predict(features)

        normal_ct = 0
        attack_ct = 0

        log(f"  {'#':<6} {'Result':<30} {'Attack Type'}\n","bold")
        log("─" * 55 + "\n","dim")

        for i, p in enumerate(preds):
            p    = int(p)
            name = REVERSE_MAP.get(p, f"class-{p}")
            if p == 0:
                log(f"  {i+1:<6} ","dim")
                log(f"{'✔  NORMAL':<30}\n","green")
                normal_ct += 1
            else:
                log(f"  {i+1:<6} ","dim")
                log(f"{'⚠  ATTACK':<30}","red")
                log(f" [{name.upper()}]\n")
                attack_ct += 1

        log("─" * 55 + "\n","dim")
        log(f"\n  Normal  samples : {normal_ct}\n","green")
        log(f"  Attack  samples : {attack_ct}\n","red")
        log(f"  Total   samples : {len(preds)}\n\n")
        set_status(
            f"● {attack_ct} ATTACKS FOUND" if attack_ct else "● ALL NORMAL",
            WARN_COL if attack_ct else ACCENT2)
    except Exception as e:
        log(f"ERROR: {e}\n","red"); set_status("● ERROR",WARN_COL)


def cb_acc_graph():
    if not any([svm_acc, random_acc, dnn_acc, elm_acc]):
        messagebox.showwarning("Warning","Run at least one algorithm first.")
        return
    vals   = [svm_acc, random_acc, dnn_acc, elm_acc]
    labels = ['SVM', 'Random\nForest', 'DNN', 'ELM']
    colors = ['#1f77b4','#2ca02c','#ff7f0e','#9467bd']

    fig, ax = plt.subplots(figsize=(8,5), facecolor="#07111f")
    ax.set_facecolor("#0d1f35")
    bars = ax.bar(labels, vals, color=colors, width=0.5, edgecolor="none")
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x()+bar.get_width()/2, v+0.2,
            f'{v:.2f}%', ha='center', color='white',
            fontsize=11, fontweight='bold')
    ax.set_ylim(0, 110)
    ax.set_ylabel("Accuracy (%)", color='white')
    ax.set_title("Algorithm Accuracy Comparison",
                 color='white', fontsize=14, fontweight='bold')
    ax.tick_params(colors='white')
    for sp in ax.spines.values(): sp.set_edgecolor("#1e3550")
    plt.tight_layout(); plt.show()


def cb_parallel():
    global parallel_time
    clear_log()
    set_status("⟳ CONNECTING…","#ffcc00")
    log("◈  Connecting to parallel server (localhost:4444)…\n\n","cyan")
    start = time.time()
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(('localhost', 4444))
        client.send('request'.encode())
        recv = client.recv(1024).decode()
        log("Output:\n" + recv + "\n","green")
    except Exception as e:
        log(f"  Server not available: {e}\n","red")
        log("  (Start the parallel server on localhost:4444)\n\n","dim")
    finally:
        parallel_time = time.time() - start
        log(f"\n  Parallel Execution Time : {parallel_time:.4f}s\n\n")
        set_status("● DONE", ACCENT2)

def cb_time_graph():
    vals   = [normal_time, parallel_time]
    labels = ['Normal\nProcessing', 'Parallel\nProcessing']
    colors = ['#1f77b4','#ff7f0e']

    fig, ax = plt.subplots(figsize=(6,4), facecolor="#07111f")
    ax.set_facecolor("#0d1f35")
    bars = ax.bar(labels, vals, color=colors, width=0.4, edgecolor="none")
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x()+bar.get_width()/2, v+0.001,
            f'{v:.4f}s', ha='center', color='white',
            fontsize=10, fontweight='bold')
    ax.set_ylabel("Time (seconds)", color='white')
    ax.set_title("Processing Time Comparison",
                 color='white', fontsize=13, fontweight='bold')
    ax.tick_params(colors='white')
    for sp in ax.spines.values(): sp.set_edgecolor("#1e3550")
    plt.tight_layout(); plt.show()

tk.Frame(root, bg="#030a14", height=22).pack(side="bottom", fill="x")
tk.Label(root, text="  Anomaly Detection IDS  |  v4.0  |  NSL-KDD  |  SVM · RF · DNN · ELM",
    bg="#030a14", fg="#1e3550",
    font=("Courier New", 8)).place(relx=0, rely=1.0, anchor="sw")


root.mainloop()