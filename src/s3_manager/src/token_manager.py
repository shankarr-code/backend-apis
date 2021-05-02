#!/usr/bin/env python3

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
Vends token based on header fields (TenantId, UserId)
"""


#import packages.jwt as jt

import json
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode
import os
import json
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

region = os.environ["AWS_REGION"]
userpool_id = os.environ["USERPOOL_ID"] # us-east-1_RvtYrwLyT
app_client_id = os.environ["APP_CLIENT_ID"] # 6m16osct28j2aclonajph6sokr
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, userpool_id)
# instead of re-downloading the public keys every time
# we download them only on cold start
# https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
with urllib.request.urlopen(keys_url) as f:
  response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']

X_TOKEN = "x-amz-security-token"
X_TENANT_ID = "x-tenant-id"
X_USER_ID = "x-user-id"


def vend(tenant_id, user_id, secret_key='aws-saas-factory'):
    """
    Vends token based on input fields. secret_key can be overriden
        :param tenant_id:
        :param user_id:
        :param secret_key='aws-saas-factory':
    """
    payload = {
        'tenant_id': tenant_id,
        'user_id': user_id
    }

    token = jt.encode(payload=payload,
                       key=secret_key,
                       algorithm='HS256').decode('utf-8')
    return token


def get_header(event, secret_key='aws-saas-factory'):
    """
    Return tenant_id, user_id, token
        :param event:
        :param secret_key='aws-saas-factory':
    """
    if X_TOKEN in event:
        logger.info("token_manager->get_header: Found token")
        token = event[X_TOKEN]
        decoded_token = get_decoded_token_cognito(token)
        tenant_id = decoded_token.get("custom:tenant")
        user_id = decoded_token.get("cognito:username")
    else:
        logger.info("token_manager->get_header: token missing")
        tenant_id = event.get(X_TENANT_ID)
        user_id = event.get(X_USER_ID)
        if not tenant_id or not user_id:
            return {}
        token = vend(tenant_id, user_id, secret_key)

    return {
        "token": token,
        "tenant_id": tenant_id,
        "user_id": user_id,
    }


def get_decoded_token(token, secret_key='aws-saas-factory'):
    """
    Decodes token using PyJWT library
        :param token:
        :param secret_key='aws-saas-factory':
    """
    return jt.decode(jwt=token,
                      key=secret_key,
                      algorithm='HS256')

def get_decoded_token_cognito(token):
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        print('Public key not found in jwks.json')
        return False
    # construct the public key
    public_key = jwk.construct(keys[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return False
    print('Signature successfully verified')
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        print('Token is expired')
        return False
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims['aud'] != app_client_id:
        print('Token was not issued for this audience')
        return False
    # now we can use the claims
    print(claims)
    return claims