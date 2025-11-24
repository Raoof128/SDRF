"""GitHub token rotator using GitHub API."""

import os
import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from github import Github, GithubException, GithubIntegration


class GitHubRotator:
    """Rotator for GitHub personal access tokens and app tokens."""

    def __init__(
        self,
        token: Optional[str] = None,
        app_id: Optional[int] = None,
        app_private_key: Optional[str] = None,
        organization: Optional[str] = None,
    ):
        """Initialize GitHub rotator.

        Args:
            token: GitHub personal access token
            app_id: GitHub App ID (for app-based rotation)
            app_private_key: GitHub App private key
            organization: GitHub organization name
        """
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.app_id = app_id or os.getenv("GITHUB_APP_ID")
        self.app_private_key = app_private_key or os.getenv("GITHUB_APP_PRIVATE_KEY")
        self.organization = organization or os.getenv("GITHUB_ORG")

        if not (self.token or (self.app_id and self.app_private_key)):
            raise ValueError("Either GitHub token or App credentials required")

        # Initialize GitHub client
        if self.token:
            self.github = Github(self.token)

        # Initialize App if credentials provided
        if self.app_id and self.app_private_key:
            self.github_app = GithubIntegration(
                integration_id=self.app_id, private_key=self.app_private_key
            )
        else:
            self.github_app = None

        # Track rotation history
        self.rotation_history: List[Dict] = []

    def revoke_personal_access_token(
        self, token_to_revoke: str, token_id: Optional[int] = None
    ) -> Tuple[bool, Dict[str, str]]:
        """Revoke a GitHub personal access token.

        Args:
            token_to_revoke: The token to revoke
            token_id: Optional token ID if known

        Returns:
            Tuple of (success, details)
        """
        result = {
            "action": "revoke_github_pat",
            "timestamp": datetime.utcnow().isoformat(),
            "status": "pending",
        }

        try:
            # GitHub API doesn't directly support revoking PATs via API
            # We can only do this through OAuth apps or GitHub Apps

            if token_id:
                # If we have the token ID, we can try to delete it
                # This requires the token to have appropriate scopes
                temp_github = Github(token_to_revoke)
                user = temp_github.get_user()

                # Note: This is a conceptual approach - GitHub's actual API
                # for managing PATs is limited
                print(f"Attempting to revoke token for user {user.login}")

                result["user"] = user.login
                result["status"] = "partial"
                result["message"] = (
                    "Token marked for revocation. Manual removal recommended via GitHub Settings."
                )
            else:
                # Without token ID, best we can do is invalidate it in our systems
                result["status"] = "partial"
                result["message"] = (
                    "Token cannot be directly revoked via API. Remove manually from GitHub Settings > Personal Access Tokens."
                )

            # Add to blacklist or internal tracking
            self._add_to_blacklist(token_to_revoke)

            self.rotation_history.append(result)
            print("⚠️ Token revocation initiated. Manual removal recommended.")
            return True, result

        except GithubException as e:
            result["status"] = "failed"
            result["error"] = str(e)
            self.rotation_history.append(result)
            print(f"❌ Failed to revoke token: {e}")
            return False, result

    def rotate_github_app_token(
        self,
        installation_id: int,
        permissions: Optional[Dict[str, str]] = None,
        repositories: Optional[List[str]] = None,
    ) -> Tuple[bool, Dict[str, str]]:
        """Rotate a GitHub App installation access token.

        Args:
            installation_id: GitHub App installation ID
            permissions: Optional permissions for the new token
            repositories: Optional list of repository names

        Returns:
            Tuple of (success, details)
        """
        result = {
            "action": "rotate_github_app_token",
            "installation_id": installation_id,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "pending",
        }

        try:
            if not self.github_app:
                raise ValueError("GitHub App credentials not configured")

            print(f"Creating new installation token for installation {installation_id}")

            # Create a new installation token
            # This automatically invalidates previous tokens after a short grace period
            jwt_token = self._generate_jwt_token()

            # Use the JWT to create an installation token
            headers = {
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.github.v3+json",
            }

            import requests

            # Build the request body
            body = {}
            if permissions:
                body["permissions"] = permissions
            if repositories:
                body["repositories"] = repositories

            response = requests.post(
                f"https://api.github.com/app/installations/{installation_id}/access_tokens",
                json=body,
                headers=headers,
            )

            if response.status_code == 201:
                token_data = response.json()

                result["token"] = (
                    token_data["token"][:8] + "..." + token_data["token"][-8:]
                )  # Masked
                result["expires_at"] = token_data["expires_at"]
                result["permissions"] = token_data.get("permissions", {})
                result["repository_selection"] = token_data.get("repository_selection", "all")

                result["status"] = "success"
                result["message"] = "Successfully created new installation token"

                # Store the new token securely (example using environment variable)
                # In production, use a secrets management service
                os.environ[f"GITHUB_APP_TOKEN_{installation_id}"] = token_data["token"]

                self.rotation_history.append(result)
                print("✅ Successfully rotated GitHub App token")
                return True, result
            else:
                raise Exception(f"Failed to create token: {response.status_code} - {response.text}")

        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            self.rotation_history.append(result)
            print(f"❌ Failed to rotate GitHub App token: {e}")
            return False, result

    def _generate_jwt_token(self) -> str:
        """Generate a JWT token for GitHub App authentication.

        Returns:
            JWT token string
        """
        import jwt
        import time

        # Create JWT payload
        payload = {
            "iat": int(time.time()),
            "exp": int(time.time()) + 600,  # Token valid for 10 minutes
            "iss": self.app_id,
        }

        # Sign with the private key
        token = jwt.encode(payload, self.app_private_key, algorithm="RS256")

        return token

    def rotate_deploy_key(
        self, repo_name: str, key_title: str = "Deploy Key", read_only: bool = True
    ) -> Tuple[bool, Dict[str, str]]:
        """Rotate a repository deploy key.

        Args:
            repo_name: Repository name (owner/repo format)
            key_title: Title for the new deploy key
            read_only: Whether the key should be read-only

        Returns:
            Tuple of (success, details)
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        result = {
            "action": "rotate_deploy_key",
            "repository": repo_name,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "pending",
        }

        try:
            repo = self.github.get_repo(repo_name)

            # Generate new SSH key pair
            print(f"Generating new SSH key pair for {repo_name}")
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend()
            )

            # Get the public key
            public_key = (
                private_key.public_key()
                .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
                .decode("utf-8")
            )

            # Get the private key
            private_key_str = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            # Remove old deploy keys with similar titles
            existing_keys = repo.get_keys()
            for key in existing_keys:
                if key_title in key.title or "Rotated" in key.title:
                    try:
                        key.delete()
                        print(f"Removed old deploy key: {key.title}")
                    except:
                        pass

            # Add new deploy key
            new_key_title = f"{key_title} - Rotated {datetime.utcnow().strftime('%Y-%m-%d')}"
            new_key = repo.create_key(title=new_key_title, key=public_key, read_only=read_only)

            result["key_id"] = new_key.id
            result["key_title"] = new_key_title
            result["public_key"] = public_key[:50] + "..."  # Truncated for safety
            result["read_only"] = read_only

            # Store the private key securely
            # In production, use a secrets management service
            private_key_path = f"/tmp/{repo_name.replace('/', '_')}_deploy_key"
            with open(private_key_path, "w") as f:
                f.write(private_key_str)
            os.chmod(private_key_path, 0o600)

            result["private_key_path"] = private_key_path
            result["status"] = "success"
            result["message"] = f"Successfully rotated deploy key for {repo_name}"

            self.rotation_history.append(result)
            print("✅ Successfully rotated deploy key")
            return True, result

        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            self.rotation_history.append(result)
            print(f"❌ Failed to rotate deploy key: {e}")
            return False, result

    def rotate_webhook_secret(
        self, repo_name: str, webhook_url: str, events: Optional[List[str]] = None
    ) -> Tuple[bool, Dict[str, str]]:
        """Rotate a webhook secret.

        Args:
            repo_name: Repository name (owner/repo format)
            webhook_url: Webhook URL to update
            events: Optional list of events to trigger webhook

        Returns:
            Tuple of (success, details)
        """
        result = {
            "action": "rotate_webhook_secret",
            "repository": repo_name,
            "webhook_url": webhook_url,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "pending",
        }

        try:
            repo = self.github.get_repo(repo_name)

            # Generate new webhook secret
            new_secret = self._generate_secret(32)

            # Find the webhook
            webhooks = repo.get_hooks()
            target_webhook = None

            for webhook in webhooks:
                if webhook.config.get("url") == webhook_url:
                    target_webhook = webhook
                    break

            if not target_webhook:
                # Create new webhook if not found
                print(f"Creating new webhook for {webhook_url}")
                config = {"url": webhook_url, "secret": new_secret, "content_type": "json"}

                target_webhook = repo.create_hook(
                    name="web",
                    config=config,
                    events=events or ["push", "pull_request"],
                    active=True,
                )

                result["webhook_created"] = True
            else:
                # Update existing webhook
                print(f"Updating webhook secret for {webhook_url}")
                config = target_webhook.config
                config["secret"] = new_secret

                target_webhook.edit(
                    config=config,
                    events=events or target_webhook.events,
                    active=target_webhook.active,
                )

                result["webhook_updated"] = True

            result["webhook_id"] = target_webhook.id
            result["new_secret"] = new_secret[:8] + "..." + new_secret[-8:]  # Masked
            result["status"] = "success"
            result["message"] = "Successfully rotated webhook secret"

            # Store the secret securely
            # In production, use environment variables or secrets management
            os.environ[f"WEBHOOK_SECRET_{repo_name.replace('/', '_')}"] = new_secret

            self.rotation_history.append(result)
            print("✅ Successfully rotated webhook secret")
            return True, result

        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            self.rotation_history.append(result)
            print(f"❌ Failed to rotate webhook secret: {e}")
            return False, result

    def _generate_secret(self, length: int = 32) -> str:
        """Generate a secure random secret.

        Args:
            length: Length of the secret

        Returns:
            Generated secret string
        """
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def _add_to_blacklist(self, token: str) -> None:
        """Add a token to the blacklist.

        Args:
            token: Token to blacklist
        """
        # In production, this would update a database or cache
        # For now, we'll just track it in memory
        if not hasattr(self, "blacklisted_tokens"):
            self.blacklisted_tokens = set()

        self.blacklisted_tokens.add(token)
        print("Added token to blacklist")

    def validate_token(self, token: str) -> bool:
        """Validate that a GitHub token works.

        Args:
            token: GitHub token to validate

        Returns:
            True if token is valid
        """
        try:
            test_github = Github(token)
            user = test_github.get_user()

            # Try to access basic information
            _ = user.login

            print(f"✅ GitHub token validated for user: {user.login}")
            return True

        except Exception as e:
            print(f"❌ GitHub token validation failed: {e}")
            return False

    def get_rotation_history(self) -> List[Dict]:
        """Get history of all rotations performed.

        Returns:
            List of rotation records
        """
        return self.rotation_history
