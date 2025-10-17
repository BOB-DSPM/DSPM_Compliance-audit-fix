# app/core/aws.py
from __future__ import annotations
import boto3
from app.core.config import settings
from app.core.session import CURRENT_BOTO3_SESSION

def _active_session():
    return CURRENT_BOTO3_SESSION.get()

def client(service: str):
    s = _active_session()
    if s is not None:
        return s.client(service)
    # 세션이 없으면 기존 방식 유지
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
    return client("s3")

def cloudfront():
    return client("cloudfront")
