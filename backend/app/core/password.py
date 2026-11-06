"""Password verification and hashing interface and Argon2id implementation using pwdlib."""

from abc import ABC, abstractmethod
import argon2.exceptions
from pwdlib import PasswordHash
from pwdlib.exceptions import PwdlibError

# Reusable PasswordHash instance configured with recommended Argon2id settings
# Parameter profile: Argon2id (version=19, memory_cost=65536 KiB [64 MiB], time_cost=3 iterations, parallelism=4 lanes)
password_hash: PasswordHash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Hash a plain text password using the team-agreed Argon2id configuration.

    This helper function is designed for reuse by the registration module developer.
    Produces standard PHC-formatted Argon2id hashes:
    $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    return password_hash.hash(password)


class PasswordVerifierInterface(ABC):
    """Abstract interface for password verification and hashing.

    Decouples password verification from service and domain logic, allowing
    replaceable hashing strategies while enforcing consistent timing mitigations.
    """

    @abstractmethod
    def verify(self, password: str, hashed_password: str) -> bool:
        """Verify plain password against stored hash."""
        pass

    @abstractmethod
    def hash(self, password: str) -> str:
        """Hash a plain password for storage."""
        pass

    @abstractmethod
    def verify_dummy(self, password: str) -> bool:
        """Simulate verification to reduce timing differences when an account is not found.

        Note: This reduces timing differences between existing and non-existing accounts,
        but does not eliminate all timing artifacts (e.g. CPU cache, garbage collection).
        """
        pass


class Argon2PasswordVerifier(PasswordVerifierInterface):
    """Argon2id verifier implementing the agreed CeylonGo password hashing standard.

    - Uses pwdlib[argon2] with PasswordHash.recommended().
    - Removes the legacy bcrypt 72-byte limit; arbitrary password lengths are preserved and verified exactly.
    - Constant-time dummy verification using a valid pre-computed Argon2id hash.
    - Safely handles malformed, corrupted, or unsupported hashes by returning False (never raising 500).
    """

    # Pre-computed dummy Argon2id hash (m=65536, t=3, p=4) used to reduce timing differences
    DUMMY_HASH: str = "$argon2id$v=19$m=65536,t=3,p=4$I3o9J/jm2Hl7bmK7omTynw$MWGaeTElqiylB5WQ8k8AsJvHjWEvUTGhjI/tJaiG/OE"

    def verify(self, password: str, hashed_password: str) -> bool:
        """Verify password against stored Argon2id hash.

        Returns False safely if password or hash is empty, or if stored hash is malformed.
        """
        if not password or not hashed_password:
            return False

        try:
            return password_hash.verify(password, hashed_password)
        except (PwdlibError, argon2.exceptions.Argon2Error, ValueError, TypeError):
            # Handles malformed, corrupted, or unrecognized hashes safely without crashing
            return False

    def hash(self, password: str) -> str:
        """Hash plain password using the shared Argon2id configuration."""
        return hash_password(password)

    def verify_dummy(self, password: str) -> bool:
        """Execute a simulated Argon2id verification to reduce timing differences for nonexistent accounts."""
        try:
            password_hash.verify(password or "dummy", self.DUMMY_HASH)
        except Exception:
            pass
        return False


# Alias to maintain compatibility with any existing references
BcryptPasswordVerifier = Argon2PasswordVerifier
