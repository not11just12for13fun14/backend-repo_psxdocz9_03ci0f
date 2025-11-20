import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt

from database import db, create_document, get_documents
from schemas import Tenant, User, Plan, Subscription, AIService, Usage, CMSPage, Invoice

# Optional provider SDKs (installed via requirements). Import guarded in functions
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv("GOOGLE_GENAI_API_KEY")

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALGO = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Multi-tenant SaaS Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------
# Auth helpers
# ------------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)
    return encoded_jwt


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        user_id = payload.get("sub")
        email = payload.get("email")
        if not user_id or not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        # Fetch user
        users = get_documents("user", {"_id": {"$exists": True}, "email": email}, limit=1)
        if not users:
            raise HTTPException(status_code=401, detail="User not found")
        user = users[0]
        # Convert ObjectId to string if needed
        if "_id" in user:
            user["id"] = str(user["_id"]) 
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ------------------------
# Public endpoints
# ------------------------
@app.get("/")
def root():
    return {"ok": True, "service": "SaaS Backend", "time": datetime.now(timezone.utc).isoformat()}


class RegisterRequest(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    password: str
    tenant_name: Optional[str] = None


@app.post("/auth/register")
def register(req: RegisterRequest):
    existing = get_documents("user", {"email": req.email}, limit=1)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create user
    user = User(email=req.email, name=req.name or "", hashed_password=get_password_hash(req.password))
    user_id = create_document("user", user)

    # Create tenant owned by this user
    tenant_slug = (req.tenant_name or req.name or req.email.split("@")[0]).lower().replace(" ", "-")
    tenant = Tenant(name=req.tenant_name or f"{req.name or 'Workspace'}'s Workspace", slug=tenant_slug, created_by_user_id=user_id,
                    features={"cms": True, "billing": True, "ai": True})
    tenant_id = create_document("tenant", tenant)

    # attach to user
    db["user"].update_one({"_id": db["user"].find_one({"email": req.email})["_id"]}, {"$addToSet": {"tenant_ids": tenant_id}})
    db["user"].update_one({"_id": db["user"].find_one({"email": req.email})["_id"]}, {"$set": {f"roles.{tenant_id}": "owner"}})

    # Issue token
    token = create_access_token({"sub": user_id, "email": req.email})
    return {"access_token": token, "token_type": "bearer", "tenant_id": tenant_id}


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.post("/auth/login", response_model=Token)
def login(req: LoginRequest):
    users = get_documents("user", {"email": req.email}, limit=1)
    if not users:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = users[0]
    if not user.get("hashed_password") or not verify_password(req.password, user.get("hashed_password")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(user.get("_id")), "email": user.get("email")})
    return Token(access_token=token)


# ------------------------
# Tenant admin endpoints
# ------------------------
class UpdateTenant(BaseModel):
    name: Optional[str] = None
    logo_url: Optional[str] = None
    primary_color: Optional[str] = None
    secondary_color: Optional[str] = None
    custom_domain: Optional[str] = None
    features: Optional[Dict[str, bool]] = None


@app.get("/tenants/my")
def list_my_tenants(user=Depends(get_current_user)):
    ids = user.get("tenant_ids", [])
    if not ids:
        return []
    docs = get_documents("tenant", {"_id": {"$in": ids}})
    # normalize
    for d in docs:
        d["id"] = str(d.get("_id"))
    return docs


@app.patch("/tenants/{tenant_id}")
def update_tenant(tenant_id: str, patch: UpdateTenant, user=Depends(get_current_user)):
    role = user.get("roles", {}).get(tenant_id)
    if role not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    update = {k: v for k, v in patch.model_dump(exclude_none=True).items()}
    if not update:
        return {"ok": True}
    db["tenant"].update_one({"_id": tenant_id}, {"$set": update})
    return {"ok": True}


# ------------------------
# CMS endpoints (simple block-based page builder backend)
# ------------------------
class UpsertPage(BaseModel):
    path: str
    title: str
    blocks: list
    published: bool = True


@app.get("/cms/pages")
def list_pages(tenant_id: str):
    pages = get_documents("cmspage", {"tenant_id": tenant_id})
    for p in pages:
        p["id"] = str(p.get("_id"))
    return pages


@app.post("/cms/pages")
def upsert_page(tenant_id: str, body: UpsertPage, user=Depends(get_current_user)):
    role = user.get("roles", {}).get(tenant_id)
    if role not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    # replace by path
    existing = get_documents("cmspage", {"tenant_id": tenant_id, "path": body.path}, limit=1)
    doc = CMSPage(tenant_id=tenant_id, path=body.path, title=body.title, blocks=body.blocks, published=body.published)
    if existing:
        db["cmspage"].update_one({"_id": existing[0]["_id"]}, {"$set": doc.model_dump()})
        return {"ok": True}
    else:
        page_id = create_document("cmspage", doc)
        return {"ok": True, "id": page_id}


# ------------------------
# AI services catalog and usage metering
# ------------------------
class UpsertService(BaseModel):
    key: str
    display_name: str
    pricing_per_1k_tokens_cents: int
    input_multiplier: float = 1.0
    output_multiplier: float = 1.0
    enabled: bool = True


@app.get("/ai/services")
def list_ai_services():
    svcs = get_documents("aiservice", {})
    for s in svcs:
        s["id"] = str(s.get("_id"))
    return svcs


@app.post("/ai/services")
def upsert_ai_service(body: UpsertService, user=Depends(get_current_user)):
    # Platform admin-only in real world; here allow any authenticated to seed
    existing = get_documents("aiservice", {"key": body.key}, limit=1)
    doc = AIService(**body.model_dump())
    if existing:
        db["aiservice"].update_one({"_id": existing[0]["_id"]}, {"$set": doc.model_dump()})
        return {"ok": True}
    else:
        sid = create_document("aiservice", doc)
        return {"ok": True, "id": sid}


class AIRequest(BaseModel):
    tenant_id: str
    service_key: str
    prompt: str
    model: Optional[str] = None


def _call_provider(service_key: str, prompt: str, override_model: Optional[str] = None) -> Tuple[str, int, int, int, Optional[str]]:
    """
    Returns: completion_text, prompt_tokens, completion_tokens, total_tokens, request_id
    """
    key = service_key.lower()
    # ---------------- OpenAI ----------------
    if key.startswith("openai"):
        api_key = OPENAI_API_KEY
        if not api_key:
            raise RuntimeError("Missing OPENAI_API_KEY")
        try:
            from openai import OpenAI
            client = OpenAI(api_key=api_key)
            model = override_model or key.split(":", 1)[1] if ":" in key else (override_model or "gpt-4o-mini")
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
            )
            choice = resp.choices[0]
            text = choice.message.content or ""
            usage = resp.usage
            pt = int(getattr(usage, "prompt_tokens", 0) or 0)
            ct = int(getattr(usage, "completion_tokens", 0) or 0)
            tt = int(getattr(usage, "total_tokens", pt + ct))
            rid = getattr(resp, "id", None)
            return text, pt, ct, tt, rid
        except Exception as e:
            raise RuntimeError(f"OpenAI error: {str(e)[:200]}")

    # ---------------- Anthropic ----------------
    if key.startswith("anthropic"):
        api_key = ANTHROPIC_API_KEY
        if not api_key:
            raise RuntimeError("Missing ANTHROPIC_API_KEY")
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            model = override_model or key.split(":", 1)[1] if ":" in key else (override_model or "claude-3-5-sonnet-latest")
            resp = client.messages.create(
                model=model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            # content is list of blocks
            text = ""
            if resp.content and len(resp.content) > 0:
                block = resp.content[0]
                text = getattr(block, "text", None) or getattr(block, "content", None) or str(block)
            usage = getattr(resp, "usage", None)
            pt = int(getattr(usage, "input_tokens", 0) or 0) if usage else 0
            ct = int(getattr(usage, "output_tokens", 0) or 0) if usage else 0
            tt = int(pt + ct)
            rid = getattr(resp, "id", None)
            return text, pt, ct, tt, rid
        except Exception as e:
            raise RuntimeError(f"Anthropic error: {str(e)[:200]}")

    # ---------------- Google Gemini ----------------
    if key.startswith("gemini") or key.startswith("google"):
        api_key = GEMINI_API_KEY
        if not api_key:
            raise RuntimeError("Missing GEMINI_API_KEY")
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = override_model or key.split(":", 1)[1] if ":" in key else (override_model or "gemini-1.5-flash")
            gmodel = genai.GenerativeModel(model)
            resp = gmodel.generate_content(prompt)
            text = resp.text or ""
            # usage metadata may vary by version
            um = getattr(resp, "usage_metadata", None) or getattr(resp, "usageMetadata", None)
            pt = int(getattr(um, "prompt_token_count", 0) or getattr(um, "promptTokenCount", 0) or 0) if um else 0
            ct = int(getattr(um, "candidates_token_count", 0) or getattr(um, "candidatesTokenCount", 0) or 0) if um else 0
            tt = int(getattr(um, "total_token_count", pt + ct) or getattr(um, "totalTokenCount", pt + ct) or (pt + ct)) if um else (pt + ct)
            rid = getattr(resp, "id", None)
            return text, pt, ct, tt, rid
        except Exception as e:
            raise RuntimeError(f"Gemini error: {str(e)[:200]}")

    # Unknown provider key
    raise RuntimeError("Unsupported service key")


@app.post("/ai/complete")
def ai_complete(body: AIRequest, user=Depends(get_current_user)):
    # Find service config
    svc_list = get_documents("aiservice", {"key": body.service_key}, limit=1)
    if not svc_list:
        raise HTTPException(status_code=400, detail="Unknown service")
    svc = svc_list[0]

    # Try real provider; on failure, fallback to mocked completion
    used_provider = "mock"
    try:
        text, prompt_tokens, completion_tokens, total_tokens, request_id = _call_provider(body.service_key, body.prompt, body.model)
        used_provider = "real"
    except Exception as e:
        # Fallback to mock if provider missing or error
        prompt_tokens = max(1, int(len(body.prompt.split()) / 0.75))
        completion_tokens = max(10, min(200, int(len(body.prompt) * 0.6)))
        total_tokens = int(prompt_tokens + completion_tokens)
        request_id = None
        text = f"This is a mocked completion for service {body.service_key}. Error: {str(e)[:120]}"

    price_per_1k = float(svc.get("pricing_per_1k_tokens_cents", 100))
    input_mult = float(svc.get("input_multiplier", 1.0))
    output_mult = float(svc.get("output_multiplier", 1.0))

    cost_cents = int((prompt_tokens * input_mult + completion_tokens * output_mult) / 1000.0 * price_per_1k)

    usage = Usage(
        tenant_id=body.tenant_id,
        user_id=str(user.get("_id")),
        service_key=body.service_key,
        prompt_tokens=int(prompt_tokens),
        completion_tokens=int(completion_tokens),
        total_tokens=int(total_tokens),
        cost_cents=cost_cents,
        request_id=request_id,
    )
    create_document("usage", usage)

    return {
        "completion": text,
        "usage": {
            "prompt_tokens": int(prompt_tokens),
            "completion_tokens": int(completion_tokens),
            "total_tokens": int(total_tokens),
            "cost_cents": cost_cents,
            "mode": used_provider,
        },
    }


# ------------------------
# Subscriptions and plans (Stripe-ready placeholders)
# ------------------------
class UpsertPlan(BaseModel):
    name: str
    interval: str
    price_cents: int
    currency: str = "usd"
    features: Dict[str, Any] = {}


@app.get("/billing/plans")
def list_plans():
    plans = get_documents("plan", {})
    for p in plans:
        p["id"] = str(p.get("_id"))
    return plans


@app.post("/billing/plans")
def upsert_plan(body: UpsertPlan, user=Depends(get_current_user)):
    existing = get_documents("plan", {"name": body.name, "interval": body.interval}, limit=1)
    doc = Plan(**body.model_dump())
    if existing:
        db["plan"].update_one({"_id": existing[0]["_id"]}, {"$set": doc.model_dump()})
        return {"ok": True}
    else:
        pid = create_document("plan", doc)
        return {"ok": True, "id": pid}


class StartSubscription(BaseModel):
    tenant_id: str
    plan_id: str


@app.post("/billing/subscribe")
def start_subscription(body: StartSubscription, user=Depends(get_current_user)):
    # Here you would create a Stripe Checkout session or subscription
    sub = Subscription(tenant_id=body.tenant_id, plan_id=body.plan_id, status="active")
    sid = create_document("subscription", sub)
    return {"ok": True, "subscription_id": sid}


@app.get("/billing/usage")
def get_usage(tenant_id: str, user=Depends(get_current_user)):
    # Summarize usage cost for the month
    docs = get_documents("usage", {"tenant_id": tenant_id})
    total_cents = sum([int(d.get("cost_cents", 0)) for d in docs])
    total_tokens = sum([int(d.get("total_tokens", 0)) for d in docs])
    return {"total_cents": total_cents, "total_tokens": total_tokens}


# ------------------------
# Invoicing (PDF URL would come from generator service)
# ------------------------
class CreateInvoice(BaseModel):
    tenant_id: str
    amount_cents: int
    currency: str = "usd"
    tax_cents: int = 0
    total_cents: Optional[int] = None
    status: str = "open"


@app.post("/billing/invoices")
def create_invoice(body: CreateInvoice, user=Depends(get_current_user)):
    role = user.get("roles", {}).get(body.tenant_id)
    if role not in ["owner", "admin"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    total = body.total_cents if body.total_cents is not None else int(body.amount_cents + body.tax_cents)
    # A real implementation would generate a PDF and upload to storage
    inv = Invoice(tenant_id=body.tenant_id, number=f"INV-{int(datetime.now().timestamp())}", amount_cents=body.amount_cents,
                  currency=body.currency, tax_cents=body.tax_cents, total_cents=total, status=body.status, pdf_url=None)
    iid = create_document("invoice", inv)
    return {"ok": True, "invoice_id": iid}


# ------------------------
# Health and test
# ------------------------
@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:15]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but error: {str(e)[:80]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    # expose provider presence
    response["providers"] = {
        "openai": bool(OPENAI_API_KEY),
        "anthropic": bool(ANTHROPIC_API_KEY),
        "gemini": bool(GEMINI_API_KEY),
    }
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
