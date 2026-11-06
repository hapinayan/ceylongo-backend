"""Domain entity representing a user in the CeylonGo core system."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class UserDomain:
    """Decoupled domain representation of an authenticated user.

    Contains strictly the fields required by authentication, token issuance,
    and role checks without coupling to a specific database engine or ORM.
    """
    id: int  # Database integer identifier matching dbo.Users.UserId
    name: str  # Display name matching dbo.Users.DisplayName
    email: str
    password_hash: str
    role: Optional[str] = None  # None if user has no assigned role; never str(None)
    is_active: bool = True
