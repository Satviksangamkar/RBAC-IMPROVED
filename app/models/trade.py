"""Trade-related Pydantic models."""
from pydantic import BaseModel, Field


class TradeExecution(BaseModel):
    """Trade execution request model."""
    symbol: str
    account_id: str = Field(..., description="Account ID for trade execution")
    quantity: float
    order_type: str = Field("market", pattern=r"^(market|limit)$") 