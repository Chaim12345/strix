"""The stub LLM serves valid OpenAI-compatible completions on loopback."""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request

import pytest


@pytest.fixture()
def stub_server():
    proc = subprocess.Popen(
        [sys.executable, "-m", "strix.integrations.atlas.stub_llm", "--port", "8412"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    for _ in range(50):
        try:
            urllib.request.urlopen("http://127.0.0.1:8412/v1/chat/completions", timeout=0.2)
        except Exception:
            time.sleep(0.1)
        else:
            break
    yield proc
    proc.terminate()
    proc.wait(timeout=5)


def test_chat_completions_shape(stub_server):
    req = urllib.request.Request(
        "http://127.0.0.1:8412/v1/chat/completions",
        data=json.dumps(
            {"model": "stub-model", "messages": [{"role": "user", "content": "hi"}]}
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        body = json.loads(resp.read())
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"]["role"] == "assistant"
    assert "stub-llm deterministic response" in body["choices"][0]["message"]["content"]
    assert body["model"] == "stub-model"
