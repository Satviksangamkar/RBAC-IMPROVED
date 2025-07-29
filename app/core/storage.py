"""Optimized storage interfaces and implementations for performance."""
import ssl
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import List, Set, Optional, Union, Any, Dict
import redis
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# Global thread pool for Redis operations - reuse threads for better performance
_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="redis-pool")


class StorageInterface(ABC):
    """Abstract storage interface for database independence."""
    
    @abstractmethod
    async def ping(self) -> bool:
        pass

    @abstractmethod
    async def close(self):
        pass

    @abstractmethod
    async def hgetall(self, key: str) -> dict:
        pass

    @abstractmethod
    async def hset(self, key: str, mapping: dict):
        pass

    @abstractmethod
    async def exists(self, key: str) -> bool:
        pass

    @abstractmethod
    async def smembers(self, key: str) -> Set[str]:
        pass

    @abstractmethod
    async def sadd(self, key: str, *members: str):
        pass

    @abstractmethod
    async def srem(self, key: str, *members: str):
        pass

    @abstractmethod
    async def get(self, key: str) -> str:
        pass

    @abstractmethod
    async def set(self, key: str, value: str):
        pass
        
    @abstractmethod
    async def delete(self, key: str):
        pass
        
    @abstractmethod
    async def keys(self, pattern: str) -> List[str]:
        pass

    @abstractmethod
    async def sismember(self, key: str, member: str) -> bool:
        pass


class OptimizedAsyncRedisWrapper:
    """Optimized async wrapper for sync Redis client with connection pooling."""
    
    def __init__(self, sync_redis):
        self.sync_redis = sync_redis
        self._loop = None
        
    def _get_loop(self):
        """Get event loop, cache for performance."""
        if self._loop is None:
            self._loop = asyncio.get_event_loop()
        return self._loop
        
    async def _run_in_executor(self, func, *args):
        """Optimized executor method using global thread pool."""
        return await self._get_loop().run_in_executor(_executor, func, *args)
    
    # Core operations - optimized for common use cases
    async def ping(self):
        return await self._run_in_executor(self.sync_redis.ping)
    
    async def hgetall(self, key: str) -> dict:
        return await self._run_in_executor(self.sync_redis.hgetall, key)
    
    async def hset(self, key: str, mapping: dict):
        return await self._run_in_executor(self.sync_redis.hset, key, mapping=mapping)
    
    async def exists(self, key: str) -> bool:
        return bool(await self._run_in_executor(self.sync_redis.exists, key))
    
    async def smembers(self, key: str) -> Set[str]:
        result = await self._run_in_executor(self.sync_redis.smembers, key)
        # Optimized decode - only decode if needed
        if result and isinstance(next(iter(result), None), bytes):
            return {member.decode() for member in result}
        return set(result) if result else set()
    
    async def sadd(self, key: str, *members: str):
        return await self._run_in_executor(self.sync_redis.sadd, key, *members)
    
    async def srem(self, key: str, *members: str):
        return await self._run_in_executor(self.sync_redis.srem, key, *members)
    
    async def get(self, key: str) -> Optional[str]:
        result = await self._run_in_executor(self.sync_redis.get, key)
        return result.decode() if isinstance(result, bytes) else result
    
    async def set(self, key: str, value: str):
        return await self._run_in_executor(self.sync_redis.set, key, value)
    
    async def delete(self, key: str):
        return await self._run_in_executor(self.sync_redis.delete, key)
    
    async def keys(self, pattern: str) -> List[str]:
        result = await self._run_in_executor(self.sync_redis.keys, pattern)
        return [k.decode() if isinstance(k, bytes) else k for k in result]
    
    async def sismember(self, key: str, member: str) -> bool:
        return bool(await self._run_in_executor(self.sync_redis.sismember, key, member))

    # Batch operations for better performance
    async def mget(self, keys: List[str]) -> List[Optional[str]]:
        """Optimized multi-get operation."""
        result = await self._run_in_executor(self.sync_redis.mget, keys)
        return [r.decode() if isinstance(r, bytes) and r else r for r in result]
    
    async def mset(self, mapping: Dict[str, str]):
        """Optimized multi-set operation."""
        return await self._run_in_executor(self.sync_redis.mset, mapping)


class RedisStorage(StorageInterface):
    """Optimized Redis storage implementation with connection pooling."""
    
    def __init__(self, host: str, port: int, username: Optional[str] = None, password: Optional[str] = None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.redis_client: Optional[redis.Redis] = None
        self.async_redis: Optional[OptimizedAsyncRedisWrapper] = None
        self._connection_pool = None
    
    async def connect(self) -> bool:
        """Optimized connection with proper SSL handling."""
        try:
            # Base connection pool configuration
            pool_config = {
                "host": self.host,
                "port": self.port,
                "decode_responses": True,
                "max_connections": 20,
                "retry_on_timeout": True,
                "socket_keepalive": True,
                "socket_keepalive_options": {},
                "health_check_interval": 30,
                "socket_connect_timeout": 5,
                "socket_timeout": 5
            }
            
            if self.username:
                pool_config["username"] = self.username
            if self.password:
                pool_config["password"] = self.password
            
            # Try different connection methods
            connection_methods = [
                {"ssl": False},  # Try non-SSL first
                {"ssl": True, "ssl_cert_reqs": None},  # SSL with no cert requirements
                {"connection_class": redis.SSLConnection, "ssl_cert_reqs": None}  # Alternative SSL method
            ]
            
            for ssl_config in connection_methods:
                try:
                    # Merge SSL config with base config
                    current_config = {**pool_config, **ssl_config}
                    
                    self._connection_pool = redis.ConnectionPool(**current_config)
                    self.redis_client = redis.Redis(connection_pool=self._connection_pool)
                    
                    # Test connection
                    await asyncio.get_event_loop().run_in_executor(_executor, self.redis_client.ping)
                    
                    self.async_redis = OptimizedAsyncRedisWrapper(self.redis_client)
                    ssl_status = "SSL" if ssl_config.get("ssl", False) else "no SSL"
                    logger.info(f"Connected to Redis at {self.host}:{self.port} ({ssl_status})")
                    return True
                    
                except Exception as e:
                    ssl_status = "SSL" if ssl_config.get("ssl", False) else "non-SSL"
                    logger.debug(f"Redis {ssl_status} connection failed: {e}")
                    continue
                    
            return False
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            return False
    
    async def close(self):
        """Clean connection shutdown."""
        try:
            if self._connection_pool:
                await asyncio.get_event_loop().run_in_executor(_executor, self._connection_pool.disconnect)
            logger.info("Redis connection pool closed")
        except Exception as e:
            logger.warning(f"Error closing Redis connection: {e}")
    
    # Delegate operations to optimized async wrapper
    async def ping(self) -> bool:
        return await self.async_redis.ping()
    
    async def hgetall(self, key: str) -> dict:
        return await self.async_redis.hgetall(key)
    
    async def hset(self, key: str, mapping: dict):
        return await self.async_redis.hset(key, mapping)
    
    async def exists(self, key: str) -> bool:
        return await self.async_redis.exists(key)
    
    async def smembers(self, key: str) -> Set[str]:
        return await self.async_redis.smembers(key)
    
    async def sadd(self, key: str, *members: str):
        return await self.async_redis.sadd(key, *members)
    
    async def srem(self, key: str, *members: str):
        return await self.async_redis.srem(key, *members)
    
    async def get(self, key: str) -> str:
        return await self.async_redis.get(key)
    
    async def set(self, key: str, value: str):
        return await self.async_redis.set(key, value)
    
    async def delete(self, key: str):
        return await self.async_redis.delete(key)
    
    async def keys(self, pattern: str) -> List[str]:
        return await self.async_redis.keys(pattern)
    
    async def sismember(self, key: str, member: str) -> bool:
        return await self.async_redis.sismember(key, member)


class InMemoryStorage(StorageInterface):
    """Optimized in-memory storage for development and testing."""
    
    def __init__(self):
        self._data: Dict[str, Any] = {}
        self._sets: Dict[str, Set[str]] = {}
        self._hashes: Dict[str, Dict[str, str]] = {}
        self._lock = asyncio.Lock()  # Thread safety for async operations
    
    async def ping(self) -> bool:
        return True
    
    async def close(self):
        async with self._lock:
            self._data.clear()
            self._sets.clear()
            self._hashes.clear()
    
    async def hgetall(self, key: str) -> dict:
        async with self._lock:
            return self._hashes.get(key, {}).copy()
    
    async def hset(self, key: str, mapping: dict):
        async with self._lock:
            if key not in self._hashes:
                self._hashes[key] = {}
            self._hashes[key].update(mapping)
    
    async def exists(self, key: str) -> bool:
        async with self._lock:
            return key in self._data or key in self._sets or key in self._hashes
    
    async def smembers(self, key: str) -> Set[str]:
        async with self._lock:
            return self._sets.get(key, set()).copy()
    
    async def sadd(self, key: str, *members: str):
        async with self._lock:
            if key not in self._sets:
                self._sets[key] = set()
            self._sets[key].update(members)
    
    async def srem(self, key: str, *members: str):
        async with self._lock:
            if key in self._sets:
                self._sets[key].discard(*members)
    
    async def get(self, key: str) -> str:
        async with self._lock:
            return self._data.get(key)
    
    async def set(self, key: str, value: str):
        async with self._lock:
            self._data[key] = value
    
    async def delete(self, key: str):
        async with self._lock:
            self._data.pop(key, None)
            self._sets.pop(key, None)
            self._hashes.pop(key, None)
    
    async def keys(self, pattern: str) -> List[str]:
        async with self._lock:
            # Simple pattern matching for in-memory
            import fnmatch
            all_keys = set(self._data.keys()) | set(self._sets.keys()) | set(self._hashes.keys())
            return [k for k in all_keys if fnmatch.fnmatch(k, pattern)]
    
    async def sismember(self, key: str, member: str) -> bool:
        async with self._lock:
            return member in self._sets.get(key, set()) 