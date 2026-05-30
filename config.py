from pydantic import BaseModel

class AWSCredentials(BaseModel):
    access_key_id: str
    secret_access_key: str
    region: str

class AuditConfig(BaseModel):
    credentials: AWSCredentials