import configparser
import json
import boto3
import os
from botocore.exceptions import ClientError
from kubernetes import client, config

K8_HOST = os.environ["K8_HOST"]
K8_TOKEN_SECRET = os.environ["K8_TOKEN_SECRET"]

cf = boto3.client('cloudformation')
session = boto3.session.Session()
sm = session.client(service_name='secretsmanager')


def _get_stack_output(stack_name):
    result = {}
    response = cf.describe_stacks(StackName=stack_name)
    stack = response["Stacks"][0]
    outputs = stack['Outputs']
    for output in outputs:
        result[output["OutputKey"]] = output["OutputValue"]
    
    return result


def _get_secret(secret_id, secret_key):
    try:
        get_secret_value_response = sm.get_secret_value(
            SecretId=secret_id
        )
    except ClientError as e:
        raise e
    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response['SecretString']
    secret_o = json.loads(secret)
    return secret_o[secret_key]

def _get_k8_client_instance():
    configuration = client.Configuration() 
    configuration.host = K8_HOST
    configuration.verify_ssl=False

    token = _get_secret(K8_TOKEN_SECRET, "K8_TOKEN")

    configuration.api_key={"authorization": f"Bearer {token}"}
    client.Configuration.set_default(configuration)
    api_client = client.ApiClient()
    api_instance = client.CustomObjectsApi(api_client)

    return api_instance

def _create_primaza_registered_service(output, stack_name):
    api_instance = _get_k8_client_instance()

    sed = []
    sci = []
    sci.append({"name": "type", "value": output.pop("type")})
    sci.append({"name": "provider", "value": "aws"})

    for key, value in output.items():
        sed.append({"name": key, "value": value})

    metadata = {
        "name": stack_name,
        "namespace": "primaza-system"
    }

    spec = {
        "serviceClassIdentity": sci,
        "serviceEndpointDefinition": sed,
        "sla": "L3"
    }

    rs_body = { 
        "apiVersion": "primaza.io/v1alpha1", 
        "kind": "RegisteredService",
        "metadata": metadata,
        "spec": spec
    }
             

    api_response = api_instance.create_namespaced_custom_object(
        group="primaza.io",
        version="v1alpha1",
        namespace="primaza-system",
        plural="registeredservices",
        body=rs_body)

def _remove_primaza_registered_service(stack_name):
    api_instance = _get_k8_client_instance()
    api_response = api_instance.delete_namespaced_custom_object(
        group="primaza.io",
        version="v1alpha1",
        namespace="primaza-system",
        plural="registeredservices",
        name=stack_name)

def lambda_handler(event, context):
    message = event["Records"][0]["Sns"]["Message"]
    config = configparser.ConfigParser()
    config.read_string(f"[message]\n{message}")
    resource_type = config["message"]["ResourceType"].strip("'")
    status = config["message"]["ResourceStatus"].strip("'")
    if resource_type == "AWS::CloudFormation::Stack" and status == "CREATE_COMPLETE":
        stack_id = config["message"]["StackId"].strip("'")
        stack_name = config["message"]["StackName"].strip("'").lower()
        output = _get_stack_output(stack_id)
        secret_id = output["DBPasswordRef"]
        password = _get_secret(secret_id, "password")
        output["DBPassword"] = password
        print(f"Registering New Service {stack_name}")
        _create_primaza_registered_service(output, stack_name)
        #print(json.dumps(output, indent=4))
    elif resource_type == "AWS::CloudFormation::Stack" and status == "DELETE_COMPLETE":
        stack_name = config["message"]["StackName"].strip("'").lower()
        print(f"Deleting Registered Service {stack_name}")
        _remove_primaza_registered_service(stack_name)

    # stack_id = "arn:aws:cloudformation:us-east-2:158037052379:stack/SC-158037052379-pp-ymuvhwtaqob4m/6b077100-c3ff-11ed-84b7-0a4fd48181ea"
    # output = _get_stack_output(stack_id)
    # secret_id = output["DBPasswordRef"]
    # password = _get_secret(secret_id, "password")
    # output["DBPassword"] = password
    # output["type"] = "aurora-mysql"
    # print(json.dumps(output, indent=4))
    
    # _create_primaza_registered_service(output, "quediceservice")

    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Service Catalag Discovery!')
    }
