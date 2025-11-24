"""AWS secret key rotator using boto3."""

import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError


class AWSRotator:
    """Rotator for AWS access keys and secrets."""

    def __init__(
        self,
        region: str = "us-east-1",
        assume_role_arn: Optional[str] = None,
        profile_name: Optional[str] = None,
    ):
        """Initialize AWS rotator.

        Args:
            region: AWS region
            assume_role_arn: ARN of role to assume for rotation (optional)
            profile_name: AWS profile name to use (optional)
        """
        self.region = region
        self.assume_role_arn = assume_role_arn
        self.profile_name = profile_name

        # Initialize AWS clients
        self._init_clients()

        # Track rotation history
        self.rotation_history: List[Dict] = []

    def _init_clients(self) -> None:
        """Initialize AWS service clients."""
        session_kwargs = {"region_name": self.region}

        if self.profile_name:
            session_kwargs["profile_name"] = self.profile_name

        session = boto3.Session(**session_kwargs)

        # Assume role if specified
        if self.assume_role_arn:
            sts = session.client("sts")
            assumed_role = sts.assume_role(
                RoleArn=self.assume_role_arn, RoleSessionName="SecretRotation"
            )

            credentials = assumed_role["Credentials"]
            session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=self.region,
            )

        # Initialize service clients
        self.iam = session.client("iam")
        self.secretsmanager = session.client("secretsmanager")
        self.ssm = session.client("ssm")
        self.sts = session.client("sts")

    def rotate_iam_access_key(
        self, access_key_id: str, user_name: Optional[str] = None
    ) -> Tuple[bool, Dict[str, str]]:
        """Rotate an IAM access key.

        Args:
            access_key_id: The access key ID to rotate
            user_name: IAM user name (will be detected if not provided)

        Returns:
            Tuple of (success, details)
        """
        result = {
            "action": "rotate_iam_access_key",
            "access_key_id": access_key_id,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "pending",
        }

        try:
            # Get user name if not provided
            if not user_name:
                user_name = self._get_user_for_access_key(access_key_id)
                if not user_name:
                    result["status"] = "failed"
                    result["error"] = "Could not determine user for access key"
                    self.rotation_history.append(result)
                    return False, result

            result["user_name"] = user_name

            # Step 1: Create new access key
            print(f"Creating new access key for user {user_name}")
            new_key_response = self.iam.create_access_key(UserName=user_name)
            new_access_key = new_key_response["AccessKey"]

            result["new_access_key_id"] = new_access_key["AccessKeyId"]

            # Step 2: Deactivate old key
            print(f"Deactivating old key {access_key_id}")
            self.iam.update_access_key(
                UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
            )

            result["old_key_deactivated"] = True

            # Step 3: Wait a bit for propagation
            time.sleep(5)

            # Step 4: Delete old key (optional, based on policy)
            # Note: In production, you might want to keep it inactive for a while
            try:
                print(f"Deleting old key {access_key_id}")
                self.iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
                result["old_key_deleted"] = True
            except ClientError as e:
                print(f"Warning: Could not delete old key: {e}")
                result["old_key_deleted"] = False

            # Step 5: Store new key in Secrets Manager (optional)
            secret_arn = self._store_in_secrets_manager(
                user_name, new_access_key["AccessKeyId"], new_access_key["SecretAccessKey"]
            )

            if secret_arn:
                result["secret_arn"] = secret_arn

            result["status"] = "success"
            result["message"] = f"Successfully rotated access key for user {user_name}"

            self.rotation_history.append(result)
            print(f"✅ Successfully rotated access key for {user_name}")
            return True, result

        except ClientError as e:
            result["status"] = "failed"
            result["error"] = str(e)
            self.rotation_history.append(result)
            print(f"❌ Failed to rotate access key: {e}")
            return False, result

    def _get_user_for_access_key(self, access_key_id: str) -> Optional[str]:
        """Get IAM user name for an access key.

        Args:
            access_key_id: The access key ID

        Returns:
            User name or None if not found
        """
        try:
            # List all users and check their access keys
            paginator = self.iam.get_paginator("list_users")

            for page in paginator.paginate():
                for user in page["Users"]:
                    user_name = user["UserName"]

                    # List access keys for this user
                    keys_response = self.iam.list_access_keys(UserName=user_name)

                    for key_metadata in keys_response["AccessKeyMetadata"]:
                        if key_metadata["AccessKeyId"] == access_key_id:
                            return user_name

        except ClientError as e:
            print(f"Error finding user for access key: {e}")

        return None

    def _store_in_secrets_manager(
        self, user_name: str, access_key_id: str, secret_access_key: str
    ) -> Optional[str]:
        """Store new credentials in AWS Secrets Manager.

        Args:
            user_name: IAM user name
            access_key_id: New access key ID
            secret_access_key: New secret access key

        Returns:
            Secret ARN or None if failed
        """
        secret_name = f"rotated-credentials/{user_name}"
        secret_value = json.dumps(
            {
                "AccessKeyId": access_key_id,
                "SecretAccessKey": secret_access_key,
                "RotatedAt": datetime.utcnow().isoformat(),
            }
        )

        try:
            # Try to update existing secret
            response = self.secretsmanager.update_secret(
                SecretId=secret_name, SecretString=secret_value
            )
            print(f"Updated secret in Secrets Manager: {secret_name}")
            return response["ARN"]

        except self.secretsmanager.exceptions.ResourceNotFoundException:
            # Create new secret
            try:
                response = self.secretsmanager.create_secret(
                    Name=secret_name,
                    SecretString=secret_value,
                    Description=f"Rotated credentials for IAM user {user_name}",
                )
                print(f"Created new secret in Secrets Manager: {secret_name}")
                return response["ARN"]

            except ClientError as e:
                print(f"Error storing secret: {e}")
                return None

        except ClientError as e:
            print(f"Error updating secret: {e}")
            return None

    def rotate_rds_password(
        self, db_instance_identifier: str, master_username: str, new_password: Optional[str] = None
    ) -> Tuple[bool, Dict[str, str]]:
        """Rotate RDS database master password.

        Args:
            db_instance_identifier: RDS instance identifier
            master_username: Master username
            new_password: New password (generated if not provided)

        Returns:
            Tuple of (success, details)
        """
        import secrets
        import string

        result = {
            "action": "rotate_rds_password",
            "db_instance": db_instance_identifier,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "pending",
        }

        try:
            # Generate new password if not provided
            if not new_password:
                alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
                new_password = "".join(secrets.choice(alphabet) for _ in range(32))

            # Initialize RDS client
            rds = boto3.client("rds", region_name=self.region)

            # Modify the DB instance with new password
            print(f"Rotating password for RDS instance {db_instance_identifier}")
            rds.modify_db_instance(
                DBInstanceIdentifier=db_instance_identifier,
                MasterUserPassword=new_password,
                ApplyImmediately=True,
            )

            # Store new password in Secrets Manager
            secret_name = f"rds-credentials/{db_instance_identifier}"
            secret_value = json.dumps(
                {
                    "username": master_username,
                    "password": new_password,
                    "engine": "mysql",  # or postgres, etc.
                    "host": f"{db_instance_identifier}.{self.region}.rds.amazonaws.com",
                    "port": 3306,
                    "dbInstanceIdentifier": db_instance_identifier,
                }
            )

            try:
                self.secretsmanager.update_secret(SecretId=secret_name, SecretString=secret_value)
            except self.secretsmanager.exceptions.ResourceNotFoundException:
                self.secretsmanager.create_secret(
                    Name=secret_name,
                    SecretString=secret_value,
                    Description=f"RDS credentials for {db_instance_identifier}",
                )

            result["status"] = "success"
            result["secret_name"] = secret_name
            result["message"] = f"Successfully rotated RDS password for {db_instance_identifier}"

            self.rotation_history.append(result)
            print("✅ Successfully rotated RDS password")
            return True, result

        except ClientError as e:
            result["status"] = "failed"
            result["error"] = str(e)
            self.rotation_history.append(result)
            print(f"❌ Failed to rotate RDS password: {e}")
            return False, result

    def rotate_secrets_manager_secret(self, secret_name: str) -> Tuple[bool, Dict[str, str]]:
        """Rotate a secret stored in AWS Secrets Manager.

        Args:
            secret_name: Name or ARN of the secret

        Returns:
            Tuple of (success, details)
        """
        result = {
            "action": "rotate_secrets_manager_secret",
            "secret_name": secret_name,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "pending",
        }

        try:
            # Rotate the secret
            print(f"Rotating secret {secret_name}")
            response = self.secretsmanager.rotate_secret(
                SecretId=secret_name,
                RotationLambdaARN=None,  # Use default rotation
                RotationRules={"AutomaticallyAfterDays": 30},
            )

            result["status"] = "success"
            result["version_id"] = response.get("VersionId")
            result["message"] = f"Successfully initiated rotation for {secret_name}"

            self.rotation_history.append(result)
            print(f"✅ Successfully rotated secret {secret_name}")
            return True, result

        except ClientError as e:
            result["status"] = "failed"
            result["error"] = str(e)
            self.rotation_history.append(result)
            print(f"❌ Failed to rotate secret: {e}")
            return False, result

    def update_parameter_store(
        self, parameter_name: str, parameter_value: str, secure: bool = True
    ) -> bool:
        """Update a parameter in Systems Manager Parameter Store.

        Args:
            parameter_name: Name of the parameter
            parameter_value: New parameter value
            secure: Whether to store as SecureString

        Returns:
            True if successful
        """
        try:
            self.ssm.put_parameter(
                Name=parameter_name,
                Value=parameter_value,
                Type="SecureString" if secure else "String",
                Overwrite=True,
            )
            print(f"Updated parameter {parameter_name} in Parameter Store")
            return True

        except ClientError as e:
            print(f"Error updating parameter store: {e}")
            return False

    def get_rotation_history(self) -> List[Dict]:
        """Get history of all rotations performed.

        Returns:
            List of rotation records
        """
        return self.rotation_history

    def validate_new_credentials(self, access_key_id: str, secret_access_key: str) -> bool:
        """Validate that new AWS credentials work.

        Args:
            access_key_id: New access key ID
            secret_access_key: New secret access key

        Returns:
            True if credentials are valid
        """
        try:
            # Create a new session with the credentials
            test_session = boto3.Session(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                region_name=self.region,
            )

            # Try to get caller identity
            test_sts = test_session.client("sts")
            test_sts.get_caller_identity()

            print("✅ New credentials validated successfully")
            return True

        except Exception as e:
            print(f"❌ New credentials validation failed: {e}")
            return False
