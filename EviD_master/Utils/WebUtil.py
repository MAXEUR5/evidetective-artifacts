import os
import json
import requests
import time
import openai
from Utils.Logger import slog
import re

CHATANYWHERE_BASE = ""
CHATANYWHERE_KEY = ""

QWEN_BASE = ""
QWEN_KEY  = ""

'''
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {QWEN_KEY}"
}
'''

TIMEOUT = 900
RETRY = 3


class MsgEntity:
    def __init__(self, role: str, message: str):
        self.role = role
        self.message = message

    def __str__(self):
        return self.role + "\n---\n" + self.message

    def read(self):
        return self.message


client = openai.OpenAI(api_key=QWEN_KEY, base_url=QWEN_BASE, timeout=TIMEOUT)

def _extract_response_text(resp) -> str:

    output_text = getattr(resp, "output_text", None)
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    texts = []
    output_items = getattr(resp, "output", None) or []
    for item in output_items:

        item_type = item.get("type") if isinstance(item, dict) else getattr(item, "type", None)
        if item_type != "message":
            continue

        content_list = item.get("content") if isinstance(item, dict) else getattr(item, "content", None)
        if not content_list:
            continue

        for c in content_list:
            c_type = c.get("type") if isinstance(c, dict) else getattr(c, "type", None)
            if c_type == "output_text":
                t = c.get("text") if isinstance(c, dict) else getattr(c, "text", None)
                if t:
                    texts.append(t)

    merged = "\n".join(texts).strip()

    if merged:
        merged = re.sub(r"<think>.*?</think>", "", merged, flags=re.DOTALL).strip()

    return merged


def gpt_send(
    message: list,
    model: str = "gpt-5.1",
    temperature: float = 0.1,
    max_completion_tokens: int = 32 * 1024,
    effort: str = "low",
    verbosity: str = "medium",
):

    input_items = []

    for m in message:
        if hasattr(m, "role") and hasattr(m, "message"):
            role = m.role
            content = m.message
        else:
            role = m.get("role")
            content = m.get("content")

        if not role:
            continue

        text_type = "output_text" if role == "assistant" else "input_text"

        input_items.append({
            "role": role,
            "content": [{"type": text_type, "text": content or ""}],
        })

    last_err = None

    for attempt in range(RETRY):
        try:
            resp = client.responses.create(
                model=model,
                input=input_items,
                temperature=temperature,
                max_output_tokens=max_completion_tokens,
                reasoning={"effort": effort},
                text={"verbosity": verbosity},
            )

            visible = _extract_response_text(resp)

            slog.info(visible)

            usage = getattr(resp, "usage", None)
            if usage:
                try:
                    slog.info(f"[usage] {usage}")
                except Exception:
                    pass

            return MsgEntity("assistant", visible)

        except Exception as e:
            last_err = e
            slog.error(f"[OpenAI Responses API] attempt={attempt + 1}/{RETRY} error: {e}")

            if attempt == RETRY - 1:
                raise

            time.sleep(min(2 ** attempt, 10))

    raise last_err


#----------------
_THINK_PAIR_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)

def _sanitize_text(text: str) -> str:
    if not text:
        return ""

    s = text


    s = _THINK_PAIR_RE.sub("", s)

    lower = s.lower()
    tag = "</think>"
    idx = lower.rfind(tag)
    if idx != -1:
        s = s[idx + len(tag):]


    s = re.sub(r"</think\s*>", "", s, flags=re.IGNORECASE)
    s = re.sub(r"<think\s*>", "", s, flags=re.IGNORECASE)


    s = re.sub(r"```(?:json)?\s*", "", s, flags=re.IGNORECASE)
    s = s.replace("```", "")

    return s.strip()


def _extract_first_target_json_object(text: str, required_keys=("state",)) -> str:
    s = _sanitize_text(text)
    if not s:
        raise ValueError("empty response text after sanitize")

    decoder = json.JSONDecoder()


    for m in re.finditer(r"[\{\[]", s):
        i = m.start()
        try:
            obj, end = decoder.raw_decode(s[i:])
        except json.JSONDecodeError:
            continue

        if not isinstance(obj, dict):
            continue

        if any(k not in obj for k in required_keys):
            continue

        return s[i:i + end].strip()

    slog.error(s)
    raise ValueError("no target JSON object found")

def gpt_send_chat(
    message: list,
    model: str = "Qwen3-235B-A22B-Thinking-2507",
    temperature: float = 0.1,
    max_completion_tokens: int = 16 * 1024,
    effort: str = "medium",
    verbosity: str = "medium",
):

    chat_messages = []

    for m in message:
        if hasattr(m, "role") and hasattr(m, "message"):
            role = m.role
            content = m.message
        else:
            role = m.get("role")
            content = m.get("content")

        if not role:
            continue

        chat_messages.append({
            "role": role,
            "content": content or ""
        })

    #slog.info(chat_messages)
    last_err = None

    
    for attempt in range(RETRY):
        try:

            t0 = time.perf_counter()
            resp = client.chat.completions.create(
                model=model,
                messages=chat_messages,
                temperature=temperature,
                max_tokens=max_completion_tokens,
            )
            dt = time.perf_counter() - t0
            m, s = divmod(dt, 60)
            slog.info("attempt=%s time_use=%d M %.3f S", attempt + 1, int(m), s)
            
            content = resp.choices[0].message.content or ""

            visible = _extract_first_target_json_object(content)

            slog.info(visible)

            usage = getattr(resp, "usage", None)
            if usage:
                try:
                    slog.info(f"[usage] {usage}")
                except Exception:
                    pass

            return MsgEntity("assistant", visible)

        except Exception as e:
            last_err = e
            slog.error(f"[OpenAI ChatCompletions] attempt={attempt + 1}/{RETRY} error: {e}")

            if attempt == RETRY - 1:
                raise

            time.sleep(min(2 ** attempt, 10))

    raise last_err