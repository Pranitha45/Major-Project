import warnings
warnings.filterwarnings("ignore")
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

import os
os.environ['PYTHONWARNINGS'] = 'ignore'

import logging
logging.disable(logging.WARNING)

import socket
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix

from sklearn_extensions.extreme_learning_machines.elm import GenELMClassifier
from sklearn_extensions.extreme_learning_machines.random_layer import MLPRandomLayer


# -----------------------------
# Prediction Function
# -----------------------------
def prediction(X_test, cls):
    y_pred = cls.predict(X_test)
    return y_pred


# -----------------------------
# Accuracy Function
# -----------------------------
def cal_accuracy(y_test, y_pred, details):

    output = ""

    cm = confusion_matrix(y_test, y_pred)
    accuracy = accuracy_score(y_test, y_pred) * 100

    output += details + "\n"
    output += "Accuracy : " + str(accuracy) + "\n\n"
    try:
        report = classification_report(y_test, y_pred, zero_division=0)
    except TypeError:
        report = classification_report(y_test, y_pred)
    output += "Classification Report : \n" + str(report) + "\n"
    output += "Confusion Matrix : \n" + str(cm) + "\n\n"

    return output


# -----------------------------
# Load Dataset
# -----------------------------
print("Loading Dataset...")

balance_data = pd.read_csv("clean.txt")

# Features and Labels — cast to float exactly like IDS.py
vals = balance_data.values.astype(float)
X = vals[:, :-1]
Y = vals[:, -1].astype(int)

print("Dataset Loaded Successfully")
print("Total Records :", len(Y))
print("Unique Labels :", np.unique(Y))


# -----------------------------
# Train Test Split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, Y, test_size=0.2, random_state=0
)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)


# -----------------------------
# Extreme Learning Machine Model
# -----------------------------
print("Training Extreme Learning Machine Model...")

hidden_layer = MLPRandomLayer(
    n_hidden=100,
    activation_func='tanh',
    random_state=0
)

cls = GenELMClassifier(hidden_layer=hidden_layer)

cls.fit(X_train, y_train)

print("Model Training Completed")


# -----------------------------
# Prediction
# -----------------------------
prediction_data = prediction(X_test, cls)


# -----------------------------
# Accuracy Evaluation
# -----------------------------
output = cal_accuracy(
    y_test,
    prediction_data,
    "Extreme Learning Machine Algorithm Results"
)

print(output)


# -----------------------------
# Socket Server
# -----------------------------
print("Starting Distributed Server...")

s = socket.socket()
port = 4444

s.bind(('', port))
s.listen(5)

print("Server Started Successfully on Port", port)

while True:

    conn, address = s.accept()
    print("Connection from:", address)

    data = conn.recv(1024).decode()

    if not data:
        break

    print("Message from Client:", data)

    # Send ML results to client (chunked to handle large output)
    data_bytes = output.encode()
    conn.sendall(data_bytes)

    conn.close()