"""Password verification and hashing interface and provisional Bcrypt implementation."""

from abc import ABC, abstractmethod
import bcrypt


class PasswordVerifierInterface(ABC):
    """Abstract interface for password verification and hashing.

    Allows replacing the provisional Bcrypt implementation with the team's final
    chosen hashing standard (e.g., Argon2id) without altering service or domain code.
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


class BcryptPasswordVerifier(PasswordVerifierInterface):
    """Provisional Bcrypt verifier used for testing and development.

    Adheres strictly to the 72-byte limit of the bcrypt specification.
    Never silently truncates input passwords.
    """

    BCRYPT_MAX_BYTES: int = 72
    # Pre-computed dummy bcrypt hash (rounds=12) used to reduce timing differences
    DUMMY_HASH: str = "$2b$12$KIXe62p9jF6rWvH1xJ1yPe0Xv8N4g9l9h5pQ5sF8u1k7m3o5q9rTi"

    def verify(self, password: str, hashed_password: str) -> bool:
        """Verify password against bcrypt hash.

        Returns False safely if password exceeds 72 bytes or stored hash is malformed.
        """
        if not password or not hashed_password:
            return False

        try:
            pw_bytes = password.encode("utf-8")
        except UnicodeEncodeError:
            return False

        # Reject inputs exceeding 72 bytes explicitly without silent truncation
        if len(pw_bytes) > self.BCRYPT_MAX_BYTES:
            return False

        try:
            hash_bytes = hashed_password.encode("utf-8")
            return bcrypt.checkpw(pw_bytes, hash_bytes)
        except (ValueError, TypeError):
            # Handles malformed stored hashes safely without crashing
            return False

    def hash(self, password: str) -> str:
        """Hash plain password using bcrypt with 12 rounds.

        Raises ValueError if password exceeds 72 bytes.
        """
        pw_bytes = password.encode("utf-8")
        if len(pw_bytes) > self.BCRYPT_MAX_BYTES:
            raise ValueError(
                f"Password exceeds bcrypt maximum length of {self.BCRYPT_MAX_BYTES} bytes. "
                "Silent truncation is forbidden."
            )
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(pw_bytes, salt).decode("utf-8")

    def verify_dummy(self, password: str) -> bool:
        """Execute a dummy verification to reduce timing differences for nonexistent accounts."""
        self.verify(password, self.DUMMY_HASH)
        return False
