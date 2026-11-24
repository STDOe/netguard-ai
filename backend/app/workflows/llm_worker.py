"""Bounded, private process for one configured provider call."""

import json
import logging
import os
import sys
from contextlib import redirect_stdout
from typing import Literal

from pydantic import BaseModel


class PlannerReply(BaseModel):
    text: str | None = None
    error: Literal["llm_timeout", "llm_rate_limit", "llm_unavailable"] | None = None


def main() -> None:
    # Third-party handlers and print calls cannot reach the parent's request log.
    with redirect_stdout(sys.stderr):
        logging.disable(logging.CRITICAL)
        os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
        os.environ["LITELLM_LOG"] = "CRITICAL"
        try:
            import litellm

            call = json.load(sys.stdin)
            litellm.telemetry = False
            litellm.suppress_debug_info = True
            response = litellm.completion(
                model=call["model"],
                api_base=call["base"],
                api_key=call["key"],
                messages=[
                    {
                        "role": "system",
                        "content": 'Return only {"option": n} with a supplied ID.',
                    },
                    {"role": "user", "content": json.dumps(call["options"])},
                ],
                max_tokens=32,
                timeout=8,
                num_retries=0,
                stream=False,
            )
            message = response.choices[0].message
            text = message.content
            reply = PlannerReply(
                text=text
                if isinstance(text, str)
                and len(text) <= 128
                and not getattr(message, "tool_calls", None)
                else None
            )
        except Exception as error:
            if type(error).__name__ == "Timeout":
                reply = PlannerReply(error="llm_timeout")
            elif type(error).__name__ == "RateLimitError":
                reply = PlannerReply(error="llm_rate_limit")
            else:
                reply = PlannerReply(error="llm_unavailable")
    sys.stdout.write(reply.model_dump_json())


if __name__ == "__main__":
    main()
