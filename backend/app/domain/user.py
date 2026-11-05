"""Domain entity representing a user in the CeylonGo core system."""

from dataclasses import dataclass


@dataclass
class UserDomain:
    """Decoupled domain representation of an authenticated user.

    Contains strictly the fields required by authentication, token issuance,
    and role checks without coupling to a specific database engine or ORM.
    """
    id: str
    name: str
    email: str
    password_hash: str
    role: str
    is_active: bool = True
