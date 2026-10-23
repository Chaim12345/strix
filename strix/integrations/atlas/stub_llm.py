"""Deterministic OpenAI-compatible stub LLM for wiring tests and CI.

NOT a model. Serves syntactically valid /v1/chat/completions responses with a
fixed deterministic body, bound to loopback only. Purpose: prove the endpoint
abstraction (STRIX_LLM + LLM_API_BASE) routes Strix's LLM traffic to a local
OpenAI-compatible endpoint without any external account. Multi-turn agent-loop
simulation is deliberately out of scope - the StubRunner covers the
orchestration path; this proves the endpoint wiring.

Run: python -m strix.integrations.atlas.stub_llm --port 8401
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


FIXED_CONTENT = (
    "stub-llm deterministic response: no model was called; this proves endpoint wiring only"
)


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path.rstrip("/") not in ("/v1/chat/completions", "/chat/completions"):
            self.send_error(404, "stub llm: unknown path")
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "stub llm: invalid JSON")
            return
        resp = {
            "id": "chatcmpl-stub",
            "object": "chat.completion",
            "created": 0,
            "model": req.get("model", "stub-model"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": FIXED_CONTENT},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
        data = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8401)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"stub llm listening on http://127.0.0.1:{args.port}/v1 (deterministic, not a model)")
    server.serve_forever()


if __name__ == "__main__":
    main()
