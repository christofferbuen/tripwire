#!/usr/bin/env python3
"""One bounded OpenRouter compatibility request; key entered without echo.

No key is written to disk or passed as an argument. This does not deploy
Beelzebub or validate VM containment. Uses synthetic command text only.
"""
import getpass
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request


def main():
    key = getpass.getpass("Development key (hidden): ")
    if not key or any(c.isspace() for c in key):
        raise ValueError("invalid key input")
    prompt = Path(__file__).with_name("prompt.txt").read_text().strip()
    body = {"model": "deepseek/deepseek-v4-flash", "stream": False,
            "max_tokens": 512,
            "messages": [{"role": "system", "content": prompt},
                         {"role": "user", "content": "pwd"},
                         {"role": "assistant", "content": "/home/user"},
                         {"role": "user", "content": "ls /var/www"}]}
    request = urllib.request.Request("https://openrouter.ai/api/v1/chat/completions",
                                     data=json.dumps(body).encode(), headers={
                                         "Content-Type": "application/json",
                                         "Authorization": "Bearer " + key})
    with urllib.request.urlopen(request, timeout=45) as response:
        result = json.load(response)
    content = result.get("choices", [{}])[0].get("message", {}).get("content")
    if not content:
        raise ValueError("provider returned no terminal text within the token limit")
    usage = result.get("usage", {})
    print(json.dumps({"model": result.get("model"), "output": content[:512],
                      "prompt_tokens": usage.get("prompt_tokens"),
                      "completion_tokens": usage.get("completion_tokens"),
                      "cost": usage.get("cost")}, ensure_ascii=True))


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as exc:
        print("Provider HTTP error " + str(exc.code), file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError) as exc:
        print("Live check failed: " + ascii(str(exc)), file=sys.stderr)
        sys.exit(1)
