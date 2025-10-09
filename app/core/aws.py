# app/core/aws.py
import boto3
from app.core.config import settings

def client(service: str):
    return boto3.client(service, region_name=settings.AWS_REGION)

def iam():
    return client("iam")

def org():
    return client("organizations")

def sso_admin():
    return client("sso-admin")

def configservice():
    return client("config")

def _region():
    return getattr(settings, "AWS_REGION", None)

def s3():
    return boto3.client("s3", region_name=_region())

def cloudfront():
    return boto3.client("cloudfront", region_name=getattr(settings, "AWS_REGION", None))