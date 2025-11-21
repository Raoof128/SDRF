"""Azure secret rotator using Azure SDK."""

import os
import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.graphrbac import GraphRbacManagementClient
from azure.graphrbac.models import PasswordCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError


class AzureRotator:
    """Rotator for Azure service principal secrets and credentials."""
    
    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        subscription_id: Optional[str] = None
    ):
        """Initialize Azure rotator.
        
        Args:
            tenant_id: Azure tenant ID
            client_id: Service principal client ID
            client_secret: Service principal client secret
            subscription_id: Azure subscription ID
        """
        self.tenant_id = tenant_id or os.getenv('AZURE_TENANT_ID')
        self.client_id = client_id or os.getenv('AZURE_CLIENT_ID')
        self.client_secret = client_secret or os.getenv('AZURE_CLIENT_SECRET')
        self.subscription_id = subscription_id or os.getenv('AZURE_SUBSCRIPTION_ID')
        
        if not all([self.tenant_id, self.subscription_id]):
            raise ValueError("Azure tenant ID and subscription ID are required")
        
        # Initialize credentials
        if self.client_id and self.client_secret:
            self.credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret
            )
        else:
            self.credential = DefaultAzureCredential()
        
        # Initialize clients
        self._init_clients()
        
        # Track rotation history
        self.rotation_history: List[Dict] = []
    
    def _init_clients(self) -> None:
        """Initialize Azure service clients."""
        # Graph client for service principal management
        self.graph_client = GraphRbacManagementClient(
            self.credential,
            self.tenant_id
        )
        
        # Authorization client for role assignments
        self.auth_client = AuthorizationManagementClient(
            self.credential,
            self.subscription_id
        )
    
    def rotate_service_principal_secret(
        self,
        service_principal_id: str,
        secret_name: Optional[str] = None,
        validity_days: int = 90
    ) -> Tuple[bool, Dict[str, str]]:
        """Rotate a service principal client secret.
        
        Args:
            service_principal_id: The service principal object ID or application ID
            secret_name: Optional name for the new secret
            validity_days: How long the new secret should be valid
            
        Returns:
            Tuple of (success, details)
        """
        result = {
            "action": "rotate_service_principal_secret",
            "service_principal_id": service_principal_id,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "pending"
        }
        
        try:
            # Get the service principal
            print(f"Getting service principal {service_principal_id}")
            
            try:
                # Try to get by object ID first
                sp = self.graph_client.service_principals.get(service_principal_id)
            except:
                # Try to get by application ID
                sps = self.graph_client.service_principals.list(
                    filter=f"appId eq '{service_principal_id}'"
                )
                sp_list = list(sps)
                if not sp_list:
                    raise ValueError(f"Service principal not found: {service_principal_id}")
                sp = sp_list[0]
            
            result["app_id"] = sp.app_id
            result["display_name"] = sp.display_name
            
            # Generate new secret
            new_secret = self._generate_secret()
            
            # Create password credential
            password_cred = PasswordCredential(
                start_date=datetime.utcnow(),
                end_date=datetime.utcnow() + timedelta(days=validity_days),
                key_id=None,
                value=new_secret,
                custom_key_identifier=secret_name or f"Rotated-{datetime.utcnow().strftime('%Y%m%d')}"
            )
            
            # Add the new credential
            print(f"Adding new secret for service principal {sp.display_name}")
            self.graph_client.service_principals.update_password_credentials(
                sp.object_id,
                [password_cred]
            )
            
            result["new_secret_expiry"] = password_cred.end_date.isoformat()
            
            # List existing credentials to remove old ones
            existing_creds = self.graph_client.service_principals.list_password_credentials(
                sp.object_id
            )
            
            # Remove old credentials (keep only the new one and recent ones)
            old_creds_removed = 0
            for cred in existing_creds:
                if cred.end_date < datetime.utcnow():
                    # Remove expired credentials
                    try:
                        self.graph_client.service_principals.remove_password_credential(
                            sp.object_id,
                            cred.key_id
                        )
                        old_creds_removed += 1
                    except:
                        pass
            
            result["old_credentials_removed"] = old_creds_removed
            
            # Store in Key Vault if configured
            keyvault_url = os.getenv('AZURE_KEYVAULT_URL')
            if keyvault_url:
                secret_stored = self._store_in_keyvault(
                    keyvault_url,
                    f"{sp.display_name}-secret",
                    new_secret
                )
                if secret_stored:
                    result["keyvault_secret_name"] = f"{sp.display_name}-secret"
            
            result["status"] = "success"
            result["message"] = f"Successfully rotated secret for {sp.display_name}"
            result["new_secret"] = new_secret[:4] + "..." + new_secret[-4:]  # Masked
            
            self.rotation_history.append(result)
            print(f"✅ Successfully rotated service principal secret")
            return True, result
            
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            self.rotation_history.append(result)
            print(f"❌ Failed to rotate service principal secret: {e}")
            return False, result
    
    def _generate_secret(self, length: int = 32) -> str:
        """Generate a secure random secret.
        
        Args:
            length: Length of the secret
            
        Returns:
            Generated secret string
        """
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def _store_in_keyvault(
        self,
        keyvault_url: str,
        secret_name: str,
        secret_value: str
    ) -> bool:
        """Store a secret in Azure Key Vault.
        
        Args:
            keyvault_url: Key Vault URL
            secret_name: Name for the secret
            secret_value: Secret value to store
            
        Returns:
            True if successful
        """
        try:
            secret_client = SecretClient(
                vault_url=keyvault_url,
                credential=self.credential
            )
            
            secret_client.set_secret(
                secret_name,
                secret_value,
                content_type="text/plain"
            )
            
            print(f"Stored secret in Key Vault: {secret_name}")
            return True
            
        except Exception as e:
            print(f"Error storing secret in Key Vault: {e}")
            return False
    
    def rotate_storage_account_key(
        self,
        resource_group: str,
        account_name: str,
        key_name: str = "key1"
    ) -> Tuple[bool, Dict[str, str]]:
        """Rotate Azure Storage Account access key.
        
        Args:
            resource_group: Resource group name
            account_name: Storage account name
            key_name: Which key to rotate (key1 or key2)
            
        Returns:
            Tuple of (success, details)
        """
        from azure.mgmt.storage import StorageManagementClient
        
        result = {
            "action": "rotate_storage_account_key",
            "storage_account": account_name,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "pending"
        }
        
        try:
            # Initialize storage client
            storage_client = StorageManagementClient(
                self.credential,
                self.subscription_id
            )
            
            # Regenerate the key
            print(f"Regenerating {key_name} for storage account {account_name}")
            storage_client.storage_accounts.regenerate_key(
                resource_group,
                account_name,
                {"key_name": key_name}
            )
            
            # Get the new keys
            keys = storage_client.storage_accounts.list_keys(
                resource_group,
                account_name
            )
            
            new_key = None
            for key in keys.keys:
                if key.key_name == key_name:
                    new_key = key.value
                    break
            
            if new_key:
                result["new_key"] = new_key[:8] + "..." + new_key[-8:]  # Masked
                
                # Store in Key Vault if configured
                keyvault_url = os.getenv('AZURE_KEYVAULT_URL')
                if keyvault_url:
                    self._store_in_keyvault(
                        keyvault_url,
                        f"{account_name}-{key_name}",
                        new_key
                    )
                    result["keyvault_secret_name"] = f"{account_name}-{key_name}"
            
            result["status"] = "success"
            result["message"] = f"Successfully rotated {key_name} for {account_name}"
            
            self.rotation_history.append(result)
            print(f"✅ Successfully rotated storage account key")
            return True, result
            
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            self.rotation_history.append(result)
            print(f"❌ Failed to rotate storage account key: {e}")
            return False, result
    
    def rotate_cosmos_db_key(
        self,
        resource_group: str,
        account_name: str,
        key_kind: str = "primary"
    ) -> Tuple[bool, Dict[str, str]]:
        """Rotate Azure Cosmos DB account key.
        
        Args:
            resource_group: Resource group name
            account_name: Cosmos DB account name
            key_kind: Which key to rotate (primary or secondary)
            
        Returns:
            Tuple of (success, details)
        """
        from azure.mgmt.cosmosdb import CosmosDBManagementClient
        
        result = {
            "action": "rotate_cosmos_db_key",
            "cosmos_account": account_name,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "pending"
        }
        
        try:
            # Initialize Cosmos DB client
            cosmos_client = CosmosDBManagementClient(
                self.credential,
                self.subscription_id
            )
            
            # Regenerate the key
            print(f"Regenerating {key_kind} key for Cosmos DB account {account_name}")
            cosmos_client.database_accounts.regenerate_key(
                resource_group,
                account_name,
                {"key_kind": key_kind}
            )
            
            # Get the new keys
            keys = cosmos_client.database_accounts.list_keys(
                resource_group,
                account_name
            )
            
            new_key = keys.primary_master_key if key_kind == "primary" else keys.secondary_master_key
            
            if new_key:
                result["new_key"] = new_key[:8] + "..." + new_key[-8:]  # Masked
                
                # Store in Key Vault
                keyvault_url = os.getenv('AZURE_KEYVAULT_URL')
                if keyvault_url:
                    self._store_in_keyvault(
                        keyvault_url,
                        f"{account_name}-{key_kind}",
                        new_key
                    )
                    result["keyvault_secret_name"] = f"{account_name}-{key_kind}"
            
            result["status"] = "success"
            result["message"] = f"Successfully rotated {key_kind} key for {account_name}"
            
            self.rotation_history.append(result)
            print(f"✅ Successfully rotated Cosmos DB key")
            return True, result
            
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            self.rotation_history.append(result)
            print(f"❌ Failed to rotate Cosmos DB key: {e}")
            return False, result
    
    def validate_new_credentials(
        self,
        client_id: str,
        client_secret: str
    ) -> bool:
        """Validate that new Azure credentials work.
        
        Args:
            client_id: Service principal client ID
            client_secret: New client secret
            
        Returns:
            True if credentials are valid
        """
        try:
            # Create a new credential with the new secret
            test_credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            
            # Try to get a token
            token = test_credential.get_token("https://management.azure.com/.default")
            
            if token and token.token:
                print("✅ New Azure credentials validated successfully")
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Azure credentials validation failed: {e}")
            return False
    
    def get_rotation_history(self) -> List[Dict]:
        """Get history of all rotations performed.
        
        Returns:
            List of rotation records
        """
        return self.rotation_history
