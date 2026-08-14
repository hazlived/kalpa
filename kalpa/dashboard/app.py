import os
import json
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from kalpa.config import KalpaConfig
from kalpa.orchestrator.controller import KalpaController

app = FastAPI(title="KALPA Defense Operations Dashboard", version="1.1.0")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
EVIDENCE_DIR = os.path.join(PROJECT_ROOT, "evidence_bundles")
TARGETS_DIR = os.path.join(PROJECT_ROOT, "targets")

# Mount static files directory
static_dir = os.path.join(BASE_DIR, "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Execution State Tracking
crs_state = {
    "status": "IDLE",  # IDLE, RUNNING, COMPLETED, ERROR
    "last_run_target": None,
    "last_run_duration": 0.0,
    "current_logs": []
}

class RunTargetRequest(BaseModel):
    target_name: str = "vulnerable_service"
    max_fuzz_seconds: int = 30

def run_crs_task(target_path: str, max_fuzz_seconds: int):
    global crs_state
    crs_state["status"] = "RUNNING"
    crs_state["last_run_target"] = os.path.basename(target_path)
    crs_state["current_logs"].append(f"Starting CRS run on {os.path.basename(target_path)}...")
    
    try:
        config = KalpaConfig(project_root=target_path, output_dir=EVIDENCE_DIR, llm_provider="rule_based")
        config.budget.max_fuzz_seconds = max_fuzz_seconds
        controller = KalpaController(target_path, config)
        bundles = controller.run_autonomous_loop()
        crs_state["status"] = "COMPLETED"
        crs_state["current_logs"].append(f"Run completed successfully! Generated {len(bundles)} evidence bundles.")
    except Exception as e:
        crs_state["status"] = "ERROR"
        crs_state["current_logs"].append(f"Error during CRS run: {str(e)}")

@app.get("/", response_class=HTMLResponse)
def get_dashboard_index():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>KALPA Dashboard API Running. Static assets missing.</h1>"

@app.get("/api/status")
def get_system_status():
    available_targets = []
    if os.path.exists(TARGETS_DIR):
        available_targets = [
            f for f in os.listdir(TARGETS_DIR)
            if os.path.isdir(os.path.join(TARGETS_DIR, f))
        ]

    # Count bundles
    bundle_count = 0
    if os.path.exists(EVIDENCE_DIR):
        bundle_count = len([f for f in os.listdir(EVIDENCE_DIR) if os.path.isdir(os.path.join(EVIDENCE_DIR, f))])

    return {
        "status": crs_state["status"],
        "available_targets": available_targets,
        "total_evidence_bundles": bundle_count,
        "last_run_target": crs_state["last_run_target"],
        "logs": crs_state["current_logs"][-15:]
    }

@app.post("/api/run")
def trigger_crs_run(req: RunTargetRequest, background_tasks: BackgroundTasks):
    global crs_state
    if crs_state["status"] == "RUNNING":
        raise HTTPException(status_code=400, detail="CRS execution is already in progress.")

    target_path = os.path.join(TARGETS_DIR, req.target_name)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail=f"Target '{req.target_name}' not found.")

    background_tasks.add_task(run_crs_task, target_path, req.max_fuzz_seconds)
    return {"message": f"CRS execution queued for target '{req.target_name}'."}

@app.get("/api/bundles")
def list_evidence_bundles():
    if not os.path.exists(EVIDENCE_DIR):
        return []

    bundles = []
    for item in os.listdir(EVIDENCE_DIR):
        item_path = os.path.join(EVIDENCE_DIR, item)
        if os.path.isdir(item_path):
            json_file = os.path.join(item_path, "evidence_bundle.json")
            if os.path.exists(json_file):
                try:
                    with open(json_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        bundles.append({
                            "vulnerability_id": data.get("vulnerability_id", item),
                            "target_name": data.get("target_name", "unknown"),
                            "vulnerability_class": data.get("causal_explanation", {}).get("vulnerability_class"),
                            "root_cause": data.get("causal_explanation", {}).get("root_cause"),
                            "pov_confirmed": data.get("pov_payload", {}).get("confirmed", False),
                            "applied_successfully": data.get("patch_result", {}).get("applied_successfully", False),
                            "timestamp": data.get("timestamp")
                        })
                except Exception:
                    continue
    return bundles

@app.get("/api/bundles/{bundle_id}")
def get_bundle_detail(bundle_id: str):
    bundle_path = os.path.join(EVIDENCE_DIR, bundle_id)
    json_file = os.path.join(bundle_path, "evidence_bundle.json")
    if not os.path.exists(json_file):
        raise HTTPException(status_code=404, detail=f"Evidence bundle '{bundle_id}' not found.")

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
