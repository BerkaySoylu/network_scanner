import asyncio
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self, delay: float):
        self.delay = delay
        self.last_request = datetime.min

    async def acquire(self):
        """Wait if needed to maintain the rate limit."""
        now = datetime.now()
        time_since_last = (now - self.last_request).total_seconds()
        
        if time_since_last < self.delay:
            await asyncio.sleep(self.delay - time_since_last)
            
        self.last_request = datetime.now() 