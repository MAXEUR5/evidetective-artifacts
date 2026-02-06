from jinja2 import FileSystemLoader, StrictUndefined
from jinja2.sandbox import SandboxedEnvironment
import re
from jinja2 import TemplateNotFound, TemplateSyntaxError, UndefinedError
from typing import Any, Mapping

env = SandboxedEnvironment(
    loader=FileSystemLoader("/home/workspace/EviD_master/PromptTemplate", encoding="utf-8"),
    undefined=StrictUndefined, 
    autoescape=False,            
    keep_trailing_newline=True,
    variable_start_string="$map{{",
    variable_end_string="}}",
    block_start_string="$block{{",
    block_end_string="}}",
    comment_start_string="$comment{{",
    comment_end_string="}}",
    finalize=lambda v: "" if v is None else str(v),
)

env.globals.clear()
env.filters.clear()
env.tests.clear()

def template_render(temaplate_path: str, params_dict: Mapping[str, Any]) -> str:
    def _coerce(v: Any) -> Any:
        if v is None:
            return ""
        if isinstance(v, (str, int, float, bool)):
            return str(v)
        if isinstance(v, (list, tuple)):
            return [ _coerce(x) for x in v ]
        if isinstance(v, set):
            return [ _coerce(x) for x in sorted(v) ]
        if isinstance(v, dict):
            return { str(k): _coerce(val) for k, val in v.items() }
        return str(v)

    safe_params = {str(k): _coerce(val) for k, val in params_dict.items()}

    try:
        template = env.get_template(temaplate_path)
        return template.render(safe_params)
    except TemplateNotFound:
        raise FileNotFoundError(f"NOT EXIST{temaplate_path}")
    except TemplateSyntaxError as e:
        raise ValueError(f"ERROR:{e.message}(LINE {e.lineno})")
    except UndefinedError as e:
        raise KeyError(f"ARG:{e}")