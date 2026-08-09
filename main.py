import re
from typing import List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="TDS GA7 Release Gate")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")


class ActionRef(BaseModel):
    owner: str
    name: str
    ref: str


class Permissions(BaseModel):
    contents: Optional[str] = None
    packages: Optional[str] = None
    id_token: Optional[str] = None

    class Config:
        # allow arbitrary extra keys so we can detect "additional scopes"
        extra = "allow"


class Workflow(BaseModel):
    trigger: str
    permissions: dict
    testsPassed: bool
    matrixComplete: bool
    failFast: bool
    actions: List[ActionRef] = []
    environmentApproval: Optional[bool] = None


class Image(BaseModel):
    multiStage: bool
    runsAsRoot: bool
    secretMode: str
    criticalVulnerabilities: int
    digestPinned: bool


class ReleaseRequest(BaseModel):
    target: str
    event: str
    ref: str
    workflow: Workflow
    image: Image


REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


def check_permissions(permissions: dict) -> bool:
    """Return True if permissions are EXACTLY least-privilege for a release."""
    if not isinstance(permissions, dict):
        return False
    if set(permissions.keys()) != set(REQUIRED_PERMISSIONS.keys()):
        return False
    for key, expected in REQUIRED_PERMISSIONS.items():
        if permissions.get(key) != expected:
            return False
    return True


def is_valid_sha(ref: str) -> bool:
    return bool(SHA40_RE.match(ref or ""))


@app.post("/release-gate")
def release_gate(req: ReleaseRequest):
    violations = []

    # --- Permissions ---
    if not check_permissions(req.workflow.permissions):
        violations.append("EXCESS_PERMISSION")

    # --- PR trigger safety ---
    if req.workflow.trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # --- Tests / matrix / failFast hygiene ---
    if (
        not req.workflow.testsPassed
        or not req.workflow.matrixComplete
        or req.workflow.failFast is True
    ):
        violations.append("TESTS_INCOMPLETE")

    # --- Action pinning ---
    mutable_action_found = False
    for action in req.workflow.actions:
        if action.owner == "actions":
            # version tags are allowed for first-party actions
            continue
        if not is_valid_sha(action.ref):
            mutable_action_found = True
    if mutable_action_found:
        violations.append("MUTABLE_ACTION")

    # --- Image checks ---
    if not req.image.multiStage:
        violations.append("SINGLE_STAGE_IMAGE")

    if req.image.runsAsRoot:
        violations.append("ROOT_RUNTIME")

    if req.image.secretMode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if req.image.criticalVulnerabilities > 0:
        violations.append("CRITICAL_CVE")

    if not req.image.digestPinned:
        violations.append("UNPINNED_IMAGE")

    # --- Production-only checks ---
    if req.target == "production":
        if not (req.event == "push" and req.ref == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")
        if req.workflow.environmentApproval is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if not violations else "block"
    return {"decision": decision, "violations": violations}


@app.get("/")
def health():
    return {"status": "ok"}
