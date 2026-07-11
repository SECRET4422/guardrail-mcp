"""Intentionally vulnerable sample for GuardRail demos — DO NOT use in production."""

import os
import subprocess
import pickle

# Simulated leaks (fake values)
AWS_ACCESS_KEY_ID = "AKIAEXAMPLEKEY00000"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
api_key = "sk-proj-thisIsAFakeOpenAIStyleToken123456"
password = "CorrectHorseBatteryStaple!"


def search_users(db, name: str):
    # SQL injection pattern
    return db.execute(f"SELECT * FROM users WHERE name = '{name}'")


def run_user_cmd(cmd: str):
    # shell injection pattern
    subprocess.run(cmd, shell=True)
    os.system(cmd)


def load_state(blob: bytes):
    return pickle.loads(blob)


def dynamic(expr: str):
    return eval(expr)


def aliased_exec():
    # Obfuscated sink — caught by AST, not simple regex alone
    runner = eval
    data = input("payload> ")
    return runner(data)


def tainted_query(request, db):
    name = request.args.get("q")
    q = f"SELECT * FROM items WHERE q = '{name}'"
    return db.execute(q)


# Fake webhook (do not use)
SLACK = "https://example.invalid/slack-webhook/T00000000/B00000000/FAKE_DEMO_ONLY"
