from fastapi import APIRouter, Depends
from rbac import require_role

router = APIRouter(prefix="/resources", tags=["resources"])


@router.get("/articles", dependencies=[Depends(require_role("user", "admin"))])
def list_articles():
    return {"items": [
        {"id": 1, "title": "RBAC intro"},
        {"id": 2, "title": "Security basics"}
    ]}


@router.post("/articles", dependencies=[Depends(require_role("admin"))])
def create_article():
    return {"detail": "Article created (mock)"}

