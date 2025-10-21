from fastapi import Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
import pathlib

env = Environment(
    loader=FileSystemLoader(str(pathlib.Path(__file__).parent / "templates")),
    autoescape=select_autoescape()
)

def render(name: str, ctx: dict) -> HTMLResponse:
    tmpl = env.get_template(name)
    return HTMLResponse(tmpl.render(**ctx))
