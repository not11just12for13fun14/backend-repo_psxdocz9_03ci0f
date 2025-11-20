"""
Database Schemas for Multi-tenant SaaS

Each Pydantic model represents a collection in MongoDB. The collection name is the lowercase of the class name.
This schema set is minimal but production-oriented to cover:
- Tenants and branding/theme
- Users and auth profiles
- Subscriptions and plans
- Feature flags and pricing for AI services
- Usage metering (tokens/requests)
- CMS pages/blocks
- Invoices
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime

class Tenant(BaseModel):
    name: str
    slug: str = Field(..., description="Unique identifier, used in subdomain or path")
    logo_url: Optional[str] = None
    primary_color: Optional[str] = Field(None, description="Hex color e.g., #0ea5e9")
    secondary_color: Optional[str] = None
    custom_domain: Optional[str] = Field(None, description="Custom domain mapped to this tenant")
    features: Dict[str, bool] = Field(default_factory=dict)
    created_by_user_id: Optional[str] = None

class User(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    hashed_password: Optional[str] = None
    is_active: bool = True
    email_verified: bool = False
    tenant_ids: List[str] = Field(default_factory=list)
    roles: Dict[str, str] = Field(default_factory=dict, description="tenant_id -> role: owner|admin|member")

class Plan(BaseModel):
    name: str
    interval: str = Field(..., description="month|year")
    price_cents: int
    currency: str = Field("usd")
    features: Dict[str, Any] = Field(default_factory=dict)

class Subscription(BaseModel):
    tenant_id: str
    plan_id: str
    status: str = Field("active", description="active|past_due|canceled|trialing")
    current_period_end: Optional[datetime] = None
    trial_end: Optional[datetime] = None
    payment_provider: str = Field("stripe")
    provider_subscription_id: Optional[str] = None

class AIService(BaseModel):
    key: str = Field(..., description="e.g., openai,gpt-4o; anthropic, gemini, deepseek, meta-llm")
    display_name: str
    pricing_per_1k_tokens_cents: int
    input_multiplier: float = 1.0
    output_multiplier: float = 1.0
    enabled: bool = True

class Usage(BaseModel):
    tenant_id: str
    user_id: Optional[str] = None
    service_key: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_cents: int = 0
    request_id: Optional[str] = None

class CMSPage(BaseModel):
    tenant_id: str
    path: str = Field(..., description="/about, /pricing, /")
    title: str
    blocks: List[Dict[str, Any]] = Field(default_factory=list, description="Ordered content blocks")
    published: bool = True

class Invoice(BaseModel):
    tenant_id: str
    number: str
    amount_cents: int
    currency: str = "usd"
    tax_cents: int = 0
    total_cents: int = 0
    status: str = Field("paid", description="draft|open|paid|void")
    pdf_url: Optional[str] = None

# End of schemas
