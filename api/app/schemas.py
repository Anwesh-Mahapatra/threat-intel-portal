from pydantic import BaseModel
from typing import Optional, List

class ItemOut(BaseModel):
    id: int
    title: Optional[str]
    canonical_url: Optional[str]
    published_at: Optional[str]
    source: Optional[str]
    summary_short: Optional[str]

class SearchResponse(BaseModel):
    items: List[ItemOut]
    count: int
