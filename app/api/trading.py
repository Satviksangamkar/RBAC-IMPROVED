"""Trading Operations API with OAuth2 Security."""
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Security, status
from fastapi.security import SecurityScopes
from pydantic import BaseModel, Field

from app.core.storage import StorageInterface
from app.core.oauth2_security import (
    oauth2_scheme, get_current_user_with_scopes, create_scope_dependency
)
from app.core.error_handling import create_authorization_error, create_resource_not_found_error
from app.dependencies import get_storage, get_current_user
from app.models.user import UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/trading", tags=["Trading"])


# Trading-specific models
class TradeRequest(BaseModel):
    """Trade execution request."""
    symbol: str = Field(..., min_length=1, max_length=10)
    side: str = Field(..., pattern=r"^(buy|sell)$")
    quantity: float = Field(..., gt=0)
    order_type: str = Field(..., pattern=r"^(market|limit|stop)$")
    price: Optional[float] = Field(None, gt=0)
    stop_price: Optional[float] = Field(None, gt=0)


class TradeResponse(BaseModel):
    """Trade execution response."""
    trade_id: str
    symbol: str
    side: str
    quantity: float
    executed_price: float
    status: str
    timestamp: datetime
    user: str


class OrderRequest(BaseModel):
    """Order creation request."""
    symbol: str = Field(..., min_length=1, max_length=10)
    side: str = Field(..., pattern=r"^(buy|sell)$")
    quantity: float = Field(..., gt=0)
    order_type: str = Field(..., pattern=r"^(market|limit|stop|stop_limit)$")
    price: Optional[float] = Field(None, gt=0)
    stop_price: Optional[float] = Field(None, gt=0)
    time_in_force: str = Field(default="GTC", pattern=r"^(GTC|IOC|FOK|DAY)$")


class OrderResponse(BaseModel):
    """Order response."""
    order_id: str
    symbol: str
    side: str
    quantity: float
    price: Optional[float]
    order_type: str
    status: str
    created_at: datetime
    user: str


class PositionResponse(BaseModel):
    """Position response."""
    symbol: str
    quantity: float
    average_price: float
    market_value: float
    unrealized_pnl: float
    realized_pnl: float


class MarketDataResponse(BaseModel):
    """Market data response."""
    symbol: str
    bid: float
    ask: float
    last: float
    volume: int
    timestamp: datetime
    level: int = Field(description="Market data level (1 or 2)")


# Scope-based dependencies
RequireTradeExecution = create_scope_dependency(["trade:execute"])
RequireTradeCancellation = create_scope_dependency(["trade:cancel"])
RequireTradeModification = create_scope_dependency(["trade:modify"])
RequireOrderManagement = create_scope_dependency(["order:create", "order:read", "order:update", "order:delete"])
RequireMarketDataLevel1 = create_scope_dependency(["market:read", "market:read:level1"])
RequireMarketDataLevel2 = create_scope_dependency(["market:read:level2"])
RequireAccountRead = create_scope_dependency(["account:read"])


@router.post("/execute", response_model=TradeResponse)
async def execute_trade(
    trade_request: TradeRequest,
    current_user: UserResponse = Security(RequireTradeExecution),
    storage: StorageInterface = Depends(get_storage)
):
    """
    Execute a trade with proper authorization.
    Requires: trade:execute scope
    """
    try:
        # Generate trade ID
        import uuid
        trade_id = str(uuid.uuid4())
        
        # Simulate trade execution
        executed_price = trade_request.price or 100.0  # Mock price
        
        # Store trade record
        trade_record = {
            "trade_id": trade_id,
            "symbol": trade_request.symbol,
            "side": trade_request.side,
            "quantity": trade_request.quantity,
            "executed_price": executed_price,
            "status": "executed",
            "timestamp": datetime.utcnow().isoformat(),
            "user": current_user.username,
            "order_type": trade_request.order_type
        }
        
        await storage.hset(f"trade:{trade_id}", trade_record)
        await storage.sadd(f"user_trades:{current_user.username}", trade_id)
        
        logger.info(f"Trade executed: {trade_id} by {current_user.username}")
        
        return TradeResponse(
            trade_id=trade_id,
            symbol=trade_request.symbol,
            side=trade_request.side,
            quantity=trade_request.quantity,
            executed_price=executed_price,
            status="executed",
            timestamp=datetime.utcnow(),
            user=current_user.username
        )
        
    except Exception as e:
        logger.error(f"Trade execution failed: {e}")
        raise create_authorization_error("Trade execution failed")


@router.post("/orders", response_model=OrderResponse)
async def create_order(
    order_request: OrderRequest,
    current_user: UserResponse = Security(RequireOrderManagement),
    storage: StorageInterface = Depends(get_storage)
):
    """
    Create a new order.
    Requires: order:create scope
    """
    try:
        import uuid
        order_id = str(uuid.uuid4())
        
        order_record = {
            "order_id": order_id,
            "symbol": order_request.symbol,
            "side": order_request.side,
            "quantity": order_request.quantity,
            "price": order_request.price,
            "order_type": order_request.order_type,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "user": current_user.username,
            "time_in_force": order_request.time_in_force
        }
        
        await storage.hset(f"order:{order_id}", order_record)
        await storage.sadd(f"user_orders:{current_user.username}", order_id)
        
        logger.info(f"Order created: {order_id} by {current_user.username}")
        
        return OrderResponse(
            order_id=order_id,
            symbol=order_request.symbol,
            side=order_request.side,
            quantity=order_request.quantity,
            price=order_request.price,
            order_type=order_request.order_type,
            status="pending",
            created_at=datetime.utcnow(),
            user=current_user.username
        )
        
    except Exception as e:
        logger.error(f"Order creation failed: {e}")
        raise create_authorization_error("Order creation failed")


@router.get("/orders", response_model=List[OrderResponse])
async def get_orders(
    current_user: UserResponse = Security(RequireOrderManagement),
    storage: StorageInterface = Depends(get_storage)
):
    """
    Get user's orders.
    Requires: order:read scope
    """
    try:
        order_ids = await storage.smembers(f"user_orders:{current_user.username}")
        orders = []
        
        for order_id in order_ids:
            order_data = await storage.hgetall(f"order:{order_id}")
            if order_data:
                orders.append(OrderResponse(
                    order_id=order_data["order_id"],
                    symbol=order_data["symbol"],
                    side=order_data["side"],
                    quantity=float(order_data["quantity"]),
                    price=float(order_data["price"]) if order_data.get("price") else None,
                    order_type=order_data["order_type"],
                    status=order_data["status"],
                    created_at=datetime.fromisoformat(order_data["created_at"]),
                    user=order_data["user"]
                ))
        
        return orders
        
    except Exception as e:
        logger.error(f"Failed to get orders: {e}")
        raise create_authorization_error("Failed to retrieve orders")


@router.delete("/orders/{order_id}")
async def cancel_order(
    order_id: str,
    current_user: UserResponse = Security(RequireOrderManagement),
    storage: StorageInterface = Depends(get_storage)
):
    """
    Cancel an order.
    Requires: order:delete scope
    """
    try:
        # Check if order exists and belongs to user
        order_data = await storage.hgetall(f"order:{order_id}")
        
        if not order_data:
            raise create_resource_not_found_error("Order")
        
        if order_data["user"] != current_user.username:
            raise create_authorization_error("Cannot cancel another user's order")
        
        # Update order status
        await storage.hset(f"order:{order_id}", {"status": "cancelled"})
        
        logger.info(f"Order cancelled: {order_id} by {current_user.username}")
        
        return {"message": "Order cancelled successfully", "order_id": order_id}
        
    except Exception as e:
        logger.error(f"Order cancellation failed: {e}")
        raise create_authorization_error("Order cancellation failed")


@router.get("/positions", response_model=List[PositionResponse])
async def get_positions(
    current_user: UserResponse = Security(RequireAccountRead),
    storage: StorageInterface = Depends(get_storage)
):
    """
    Get user's positions.
    Requires: account:read scope
    """
    try:
        # Mock positions data
        positions = [
            PositionResponse(
                symbol="AAPL",
                quantity=100.0,
                average_price=150.0,
                market_value=15000.0,
                unrealized_pnl=500.0,
                realized_pnl=0.0
            ),
            PositionResponse(
                symbol="GOOGL",
                quantity=50.0,
                average_price=2500.0,
                market_value=125000.0,
                unrealized_pnl=-1000.0,
                realized_pnl=200.0
            )
        ]
        
        logger.info(f"Positions retrieved for {current_user.username}")
        return positions
        
    except Exception as e:
        logger.error(f"Failed to get positions: {e}")
        raise create_authorization_error("Failed to retrieve positions")


@router.get("/market-data/{symbol}", response_model=MarketDataResponse)
async def get_market_data(
    symbol: str,
    level: int = 1,
    current_user: UserResponse = Security(RequireMarketDataLevel1),
    storage: StorageInterface = Depends(get_storage)
):
    """
    Get market data for a symbol.
    Requires: market:read scope for level 1, market:read:level2 for level 2
    """
    try:
        # Check level 2 access if requested
        if level == 2:
            # This would require additional scope validation
            user_permissions = await storage.smembers(f"user_permissions:{current_user.username}")
            if "market:read:level2" not in user_permissions:
                raise create_authorization_error("Level 2 market data access denied")
        
        # Mock market data
        market_data = MarketDataResponse(
            symbol=symbol.upper(),
            bid=99.5,
            ask=100.0,
            last=99.8,
            volume=1000000,
            timestamp=datetime.utcnow(),
            level=level
        )
        
        logger.info(f"Market data retrieved: {symbol} level {level} by {current_user.username}")
        return market_data
        
    except Exception as e:
        logger.error(f"Market data retrieval failed: {e}")
        raise create_authorization_error("Market data access failed")


@router.get("/trades", response_model=List[TradeResponse])
async def get_trades(
    current_user: UserResponse = Security(RequireAccountRead),
    storage: StorageInterface = Depends(get_storage)
):
    """
    Get user's trade history.
    Requires: account:read scope
    """
    try:
        trade_ids = await storage.smembers(f"user_trades:{current_user.username}")
        trades = []
        
        for trade_id in trade_ids:
            trade_data = await storage.hgetall(f"trade:{trade_id}")
            if trade_data:
                trades.append(TradeResponse(
                    trade_id=trade_data["trade_id"],
                    symbol=trade_data["symbol"],
                    side=trade_data["side"],
                    quantity=float(trade_data["quantity"]),
                    executed_price=float(trade_data["executed_price"]),
                    status=trade_data["status"],
                    timestamp=datetime.fromisoformat(trade_data["timestamp"]),
                    user=trade_data["user"]
                ))
        
        logger.info(f"Trades retrieved for {current_user.username}")
        return trades
        
    except Exception as e:
        logger.error(f"Failed to get trades: {e}")
        raise create_authorization_error("Failed to retrieve trades")


@router.get("/account/summary")
async def get_account_summary(
    current_user: UserResponse = Security(RequireAccountRead),
    storage: StorageInterface = Depends(get_storage)
):
    """
    Get account summary.
    Requires: account:read scope
    """
    try:
        # Mock account summary
        summary = {
            "account_id": current_user.username,
            "total_value": 140000.0,
            "cash_balance": 10000.0,
            "buying_power": 40000.0,
            "day_pnl": -500.0,
            "total_pnl": 5000.0,
            "margin_used": 0.0,
            "roles": current_user.roles
        }
        
        logger.info(f"Account summary retrieved for {current_user.username}")
        return summary
        
    except Exception as e:
        logger.error(f"Account summary retrieval failed: {e}")
        raise create_authorization_error("Account summary access failed") 