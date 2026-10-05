"""Query parameters shared by the paged list endpoints."""
from fastapi import Query

# FastAPI records the parameter name on these objects, so each one is only ever the default of a parameter named after
# it.
SKIP = Query(0, ge=0)
LIMIT = Query(100, ge=1, le=500)
