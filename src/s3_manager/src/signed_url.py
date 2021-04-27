import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from botocore.signers import CloudFrontSigner

import os
from http import HTTPStatus
import constants
import helper
import policy_manager as plcymgr
import boto3
import json
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

ACCOUNT_ID = os.environ["AWS_ACCOUNT_ID"]
IAMROLE_LMDEXEC_ARN = os.environ["IAMROLE_LMDEXEC_ARN"]
NOSQL_DBTABLE_NAME = os.environ["NOSQL_DBTABLE_NAME"]
NOSQL_DBTABLE_ARN = "arn:aws:dynamodb:{0}:{1}:table/{2}".format(os.environ["AWS_REGION"],
                                                                os.environ["AWS_ACCOUNT_ID"],
                                                                NOSQL_DBTABLE_NAME)

def get_signed_url(event, context):
    
    # Build context
    query_string = event.get("queryStringParameters")
    action_type = query_string.get("action")
    key_name = query_string.get("key_name")
    content = query_string.get("content")
    obj_id = query_string.get("obj_id")

    req_header = helper.get_tenant_context(event)
    if "missing_fields" in req_header:
        return req_header
    bucket_name = "{0}-{1}".format(req_header['tenant_id'].lower(), os.environ["AWS_ACCOUNT_ID"])
    file_name = '{0}/{1}/{2}'.format(req_header['tenant_id'], req_header['user_id'], key_name)
    
    req_header.update({
        "bucket_name": bucket_name,
        "bucket_arn": "arn:aws:s3:::{0}".format(bucket_name),
        "key_name": file_name,
        "nosql_table_arn": NOSQL_DBTABLE_ARN,
        "nosql_partition_key": req_header['tenant_id'],
        "obj_id": obj_id
    })
    logger.info("get_signed_url: req header --> %s", req_header)
    policy_template = helper.get_policy_template('db_nosql')
    assume_role_policy = plcymgr.get_policy(policy_template, req_header)
    #logger.info("Policy template --> %", policy_template)
    sts_creds = helper.get_assumed_role_creds("s3", assume_role_policy)
    s3_client = helper.get_boto3_client("s3", sts_creds)
    cw_client = helper.get_boto3_client("cloudwatch", sts_creds)
    
    
    if action_type == "get_url":
        """
        1. Generate pre-signed URL for downloading file
        2. Replace get_object with put_object for generating pre-signed URL to upload file
        3. Use PUT method while uploading file using Pre-Signed URL
        """
        URL = s3_client.generate_presigned_url("get_object", Params = {"Bucket": bucket_name, "Key": key_name},  ExpiresIn=3600)
        logger.info("get_signed_url: get signed url --> %s ", URL)
        user_objects = URL
    
    if action_type == "post_url":
        """
        1. Generate pre-signed URL for downloading file
        2. Use POST method while uploading file using Pre-Signed URL
        """
        cw_client.put_metric_data(
        MetricData=[
            {
                'MetricName': 'FUNCTION_CALLED',
                'Dimensions': [
                    {
                        'Name': 'SIGNED_PUT',
                        'Value': req_header["tenant_id"]
                    },
                ],
                'Unit': 'None',
                'Value': 1
            },
        ],
        Namespace='OCTANKVIEW/TRAFFIC'
        )
        URL = s3_client.generate_presigned_url("put_object", Params = {"Bucket": bucket_name, "Key": file_name, "ContentType": content },  ExpiresIn=3600)
        #URL = s3_client.generate_presigned_post(Bucket=bucket_name, Key=file_name, Fields=None, Conditions=None, ExpiresIn=3600)
        logger.info("get_signed_url: post signed url --> %s ", URL)
        user_objects = URL

    if action_type == "get_id":
        ddb_client = helper.get_boto3_client("dynamodb", sts_creds)
        db_resp = read_metadata_db(ddb_client, req_header)
        user_objects = db_resp['Items']

    if action_type == "get_url_cf":
        cw_client.put_metric_data(
        MetricData=[
            {
                'MetricName': 'FUNCTION_CALLED',
                'Dimensions': [
                    {
                        'Name': 'SIGNED_GET',
                        'Value': req_header["tenant_id"]
                    },
                ],
                'Unit': 'None',
                'Value': 1
            },
        ],
        Namespace='OCTANKVIEW/TRAFFIC'
        )
        key_id = 'KXHVAY69A33US'
        #url = 'http://d2aihwjk7j4ii2.cloudfront.net/'+ key_name
        if req_header["tenant_id"] == "tenantA":
            url = 'http://d2xswc64piohcl.cloudfront.net/'+ key_name
        if req_header["tenant_id"] == "tenantB":
            url = 'http://d3fy5jj2zxo1s2.cloudfront.net/'+ key_name
        current_time = datetime.datetime.utcnow()
        expire_date = current_time + datetime.timedelta(minutes = 5)
        cloudfront_signer = CloudFrontSigner(key_id, rsa_signer)
        # Create a signed url that will be valid until the specfic expiry date
        # # provided using a canned policy.
        signed_url = cloudfront_signer.generate_presigned_url(url, date_less_than=expire_date)
        logger.info("signed_url: CF signed url --> %s ", signed_url)
        user_objects = signed_url

    return helper.success_response(user_objects,
                                       HTTPStatus.OK)


def read_metadata_db(ddb_client, req_header):
    """
    Returns metadata from NoSQL Database (DynamoDB)
    """
    logger.info("signed_url.read_metadata_db: req_header --> %s", json.dumps(req_header))
    try:
        response = ddb_client.query(TableName=NOSQL_DBTABLE_NAME,
                            KeyConditionExpression='tenant_id= :tenant_id and id = :id',
                            ExpressionAttributeValues={
                                ':tenant_id': {
                                    'S': req_header["tenant_id"]
                                },
                                ':id' : {
                                    'S': req_header["obj_id"]
                                }
                            })
    except Exception as e:
        logger.error("read_metadata_db: dynamodb expection  --> %s", e)
    return response

def rsa_signer(message):
    with open('private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key.sign(message, padding.PKCS1v15(), hashes.SHA1())