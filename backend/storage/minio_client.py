"""
MinIO client for object storage operations.
"""

import os
import logging
from typing import Optional, BinaryIO
from io import BytesIO

from minio import Minio
from minio.error import S3Error

logger = logging.getLogger(__name__)


class MinIOClient:
    """MinIO client wrapper for QES Platform file storage."""
    
    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        secure: bool = False
    ):
        """Initialize MinIO client."""
        self.client = Minio(
            endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=secure
        )
        self.endpoint = endpoint
        logger.info(f"MinIO client initialized for endpoint: {endpoint}")
    
    async def ensure_bucket_exists(self, bucket_name: str) -> bool:
        """Ensure bucket exists, create if not."""
        try:
            if not self.client.bucket_exists(bucket_name):
                self.client.make_bucket(bucket_name)
                logger.info(f"Created bucket: {bucket_name}")
            return True
        except S3Error as e:
            logger.error(f"Failed to ensure bucket {bucket_name}: {e}")
            return False
    
    async def upload_file(
        self,
        bucket_name: str,
        object_name: str,
        data: bytes,
        content_type: str = "application/octet-stream"
    ) -> bool:
        """Upload file data to MinIO."""
        try:
            # Ensure bucket exists
            await self.ensure_bucket_exists(bucket_name)
            
            # Upload data
            data_stream = BytesIO(data)
            self.client.put_object(
                bucket_name,
                object_name,
                data_stream,
                length=len(data),
                content_type=content_type
            )
            
            logger.info(f"Uploaded {len(data)} bytes to {bucket_name}/{object_name}")
            return True
            
        except S3Error as e:
            logger.error(f"Failed to upload to {bucket_name}/{object_name}: {e}")
            return False
    
    async def download_file(self, bucket_name: str, object_name: str) -> bytes:
        """Download file data from MinIO."""
        try:
            response = self.client.get_object(bucket_name, object_name)
            data = response.read()
            response.close()
            response.release_conn()
            
            logger.info(f"Downloaded {len(data)} bytes from {bucket_name}/{object_name}")
            return data
            
        except S3Error as e:
            logger.error(f"Failed to download {bucket_name}/{object_name}: {e}")
            raise
    
    async def file_exists(self, bucket_name: str, object_name: str) -> bool:
        """Check if file exists in MinIO."""
        try:
            self.client.stat_object(bucket_name, object_name)
            return True
        except S3Error:
            return False
    
    async def delete_file(self, bucket_name: str, object_name: str) -> bool:
        """Delete file from MinIO."""
        try:
            self.client.remove_object(bucket_name, object_name)
            logger.info(f"Deleted {bucket_name}/{object_name}")
            return True
        except S3Error as e:
            logger.error(f"Failed to delete {bucket_name}/{object_name}: {e}")
            return False
    
    async def get_file_info(self, bucket_name: str, object_name: str) -> dict:
        """Get file metadata."""
        try:
            stat = self.client.stat_object(bucket_name, object_name)
            return {
                "size": stat.size,
                "etag": stat.etag,
                "last_modified": stat.last_modified,
                "content_type": stat.content_type,
                "metadata": stat.metadata
            }
        except S3Error as e:
            logger.error(f"Failed to get info for {bucket_name}/{object_name}: {e}")
            raise


# Global MinIO client instance
_minio_client: Optional[MinIOClient] = None


def get_minio_client() -> MinIOClient:
    """Get MinIO client dependency for FastAPI."""
    global _minio_client
    
    if _minio_client is None:
        endpoint = os.getenv("MINIO_ENDPOINT", "minio:9000")
        access_key = os.getenv("MINIO_ACCESS_KEY", "admin")
        secret_key = os.getenv("MINIO_SECRET_KEY", "admin123456")
        secure = os.getenv("MINIO_SECURE", "false").lower() == "true"
        
        _minio_client = MinIOClient(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=secret_key,
            secure=secure
        )
    
    return _minio_client