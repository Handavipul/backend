import boto3
import json
import os
from typing import Dict, Any
import logging

class AWSService:
    def __init__(self):
        self.region = os.getenv('AWS_REGION', 'eu-west-2')
        self.sns_client = boto3.client('sns', region_name=self.region)
        self.sqs_client = boto3.client('sqs', region_name=self.region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=self.region)
        self.s3_client = boto3.client('s3', region_name=self.region)
        
        # Topic ARNs
        self.notification_topic_arn = os.getenv('SNS_NOTIFICATION_TOPIC_ARN', 'arn:aws:sns:eu-west-2:156346049868:avpay-notification-topic')
        self.payment_queue_url = os.getenv('SQS_PAYMENT_QUEUE_URL', 'https://sqs.eu-west-2.amazonaws.com/156346049868/avpay-payment-queue')

        print(f"Initialized AWSService with region: {self.region}, notification topic: {self.notification_topic_arn}, and payment queue URL: {self.payment_queue_url}")

    async def send_notification(self, message: str, subject: str, user_email: str):
        """Send notification via SNS"""
        try:
            response = self.sns_client.publish(
                TopicArn=self.notification_topic_arn,
                Message=message,
                Subject=subject,
                MessageAttributes={
                    'email': {
                        'DataType': 'String',
                        'StringValue': user_email
                    }
                }
            )
            return response
        except Exception as e:
            logging.error(f"SNS notification error: {e}")
            return None

    async def queue_payment_processing(self, payment_data: Dict[str, Any]):
        """Queue payment for async processing"""
        try:
            message_body = json.dumps(payment_data)
            response = self.sqs_client.send_message(
                QueueUrl=self.payment_queue_url,
                MessageBody=message_body
            )
            return response
        except Exception as e:
            logging.error(f"SQS queue error: {e}")
            return None

    async def log_metric(self, metric_name: str, value: float, unit: str = 'Count'):
        """Log custom metric to CloudWatch"""
        try:
            response = self.cloudwatch.put_metric_data(
                Namespace='PaymentGateway',
                MetricData=[
                    {
                        'MetricName': metric_name,
                        'Value': value,
                        'Unit': unit
                    }
                ]
            )
            return response
        except Exception as e:
            logging.error(f"CloudWatch metric error: {e}")
            return None

    async def store_secure_file(self, bucket_name: str, file_key: str, file_content: bytes):
        """Store file securely in S3"""
        try:
            response = self.s3_client.put_object(
                Bucket=bucket_name,
                Key=file_key,
                Body=file_content,
                ServerSideEncryption='AES256'
            )
            return response
        except Exception as e:
            logging.error(f"S3 storage error: {e}")
            return None