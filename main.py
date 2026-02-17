from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
import json
import yaml
from security import security_checks

app = FastAPI()
templates = Jinja2Templates(directory="templates") 

# json or yaml file upload
def parse_spec(content: str):

    "PARSING"
    try:
        print("JSON")
        return json.loads(content)
    except:
        print("YAML")
        return yaml.safe_load(content)

# parse request to html
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# returns object of severity counts
def summarise(issues):
    summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for issue in issues:
        summary[issue["severity"]] += 1

    return summary

# subtracts score from 100 based off how many issues
def calculate_score(issues):
    score = 100
    weights = {
        "Critical": 19,
        "High": 14,
        "Medium": 7,
        "Low": 2
    }

    for issue in issues:
        score -= weights.get(issue["severity"], 0)

    return max(score, 0)

# analyse request
@app.post("/analyze")
async def analyze(request: Request, file: UploadFile = File(None), text_input: str = Form(None)):

    content = ""

    if file and file.filename:
        content = (await file.read()).decode("utf-8")
    elif text_input and text_input.strip():
        content = text_input.strip()

    if not content:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "Please upload a file or paste an OpenAPI spec."
        })


    spec = parse_spec(content)

    issues = security_checks(spec)
    summary = summarise(issues)
    score = calculate_score(issues)

    return templates.TemplateResponse("results.html", {
        "request": request,
        "issues": issues,
        "summary": summary,
        "score": score,
        "total": len(issues)
    })


