# program to highlight the power of AWS AI/ML services
# Author: Girish Chanchlani
# Feb 13th 2022

# PLEASE NOTE: This program is not intended to be used in production environment. The aim here is to learn how to use AWS AI/ML APIs. 
# Use this at your own risk. You will incur AWS charges by using these APIs, please check individual service pricing for more details. 

import logging
from queue import Empty
import sys
import random
import time
import csv
import json
from tkinter import W
import boto3
import pprint
#import requests
from datetime import datetime

from botocore.exceptions import ClientError

CSV_HEADER = ['AccountId', 'BucketName', 'Region', 'FileExtension', 'Severity', 'FindingType',
              'FindingCount', 'Details', 'ObjectKey', 'S3Path', 'URLPath', 'FindingConsoleURL', 'Finding Creation Date', 'Object-level Public ACL']

def get_summary(finding):
    summary = []
    count = 0
    for data_type in finding['classificationDetails']['result']['sensitiveData']:
        summary.append(f"{data_type['category']}: {data_type['totalCount']}")
        count += data_type['totalCount']
    return("\n".join(summary), count)

# START OF invoke_macie

def invoke_macie(): 
#    print("INSIDE invoke_macie")
    macie = boto3.client('macie2', region_name='us-east-1')
    macie_buc = input('Enter the name of the bucket containing Pii dataset: ')
    account_id = input('Enter the AWS account ID: ')
    ans = input('Do you want to analyze a new dataset?(Y/N): ') 
    if ans == "Y": 
        jobName = "TestJobRun" + str(random.randint(0,200))
        print("Starting job: ", jobName)

        #run a one time classification job
        try:
            response = macie.create_classification_job(
                description='Test job to analyze PII data',
                jobType='ONE_TIME',
                name=jobName,
                s3JobDefinition={
                    'bucketDefinitions': [
                        {
                            'accountId': account_id,
                            'buckets': [
                                macie_buc
                            ]
                        }
                    ],
                    'scoping': {
                        'includes': {
                            'and': [
                                {
                                    'simpleScopeTerm': {
                                        'comparator': 'EQ',
                                        'key': 'OBJECT_EXTENSION',
                                        'values': [
                                            'csv',
                                        ]
                                    }
                                },
                            ]
                        }
                    }
                },
                samplingPercentage=100,
                tags={
                    'Project': 'Amazon Analyze'
                }
            )
    #        logging.debug(f'Response: {response}')
            print(response)
            job = response['jobId'] 
            print( "job id is: ", job)
        except ClientError as e:
            logging.error(e)
            sys.exit(e)

        # now the job started.. how do I wait for it? 
        try: 
            response = macie.describe_classification_job(jobId=job) 
            while response['jobStatus'] == 'RUNNING': 
                print('Job is running.. waiting for it to complete')
                time.sleep(10)
                response = macie.describe_classification_job(jobId=job)

            print('Job status is: ', response['jobStatus']) 
        except ClientError as e:
            logging.error(e)
            sys.exit(e)

        if response['jobStatus'] != "COMPLETE": 
            print('job did not successfully complete. Exiting.. ')
            sys.exit("Error"); 

    #lets check the findings 
    #to do that, have to build a finding criteria
    findingCriteria = {'criterion': {'category': {'eq': ['CLASSIFICATION']}}}
    findingCriteria = {'criterion': {'category': {'eq': ['CLASSIFICATION']}}}
    findingCriteria['criterion']['resourcesAffected.s3Bucket.name'] = {'eq': [macie_buc]}
    list_response = macie.list_findings(
            findingCriteria=findingCriteria,
            maxResults=40
            )
    findings = list_response['findingIds']
    print('number of findings found: ', len(findings))
    if len(findings) == 0:
        # No findings in this region, move along
        print("No findings available")
        sys.exit()

    #open the results csv file
    filename = "macie_results.csv"
    csvoutfile = open(filename, 'w')
    writer = csv.writer(csvoutfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
    writer.writerow(CSV_HEADER)

    # Store bucket results
    results = {
        "Low": 0,
        "Medium": 0,
        "High": 0
    }
    # Now get the meat of  these findings
    get_response = macie.get_findings(findingIds=findings)
    for f in get_response['findings']:
        bucket_name = f['resourcesAffected']['s3Bucket']['name']
        key = f['resourcesAffected']['s3Object']['key']
        summary, count = get_summary(f)
        obj_publicAccess = "Unknown"
        if 'publicAccess' in f['resourcesAffected']['s3Object']:
            obj_publicAccess = f['resourcesAffected']['s3Object']['publicAccess']
            writer.writerow([f['accountId'], bucket_name, "us-east-1",
            f['resourcesAffected']['s3Object']['extension'],
            f['severity']['description'], f['type'],
            count, summary, key,
            f"s3://{bucket_name}/{key}",
            f"https://{bucket_name}.s3.amazonaws.com/{key}",
            f"https://{'us-east-1'}.console.aws.amazon.com/macie/home?region={'us-east-1'}#findings?search=resourcesAffected.s3Bucket.name%3D{bucket_name}&macros=current&itemId={f['id']}",
            f['createdAt'], obj_publicAccess
        ])
        results[f['severity']['description']] += 1

    print(f"Exported High: {results['High']} Medium: {results['Medium']} Low: {results['Low']} ")
    csvoutfile.close()

    print("Findings results are available in file ", filename )
    print("DONE")

# Thoughts on extending this... 
# once PII data is found, enable S3 object lock on those objects  

# END OF invoke_macie

# START OF invoke_comprehend

def invoke_comprehend(): 
#    print("INSIDE invoke_comprehend")
    comprehend = boto3.client('comprehend', region_name='us-east-1')
    macie_buc = input('Enter the name of the bucket containing Pii dataset: ')
    account_id = input('Enter the AWS account ID: ')
    input_data_config = {'S3Uri': 's3://' + macie_buc}
    output_data_config = {'S3Uri': 's3://' + 'analysis-output-bucket1'}
    data_access_role = 'arn:aws:iam::' + account_id + ':role/comprehend_data_access_role'
    job_name = 'Job-started-by-girish' + str(random.randint(0,2000)) 

    input_job_name = input("Enter a job name to query for(None if you want to start a new job):")
    status = ""

    if input_job_name == "": 
        response = comprehend.start_pii_entities_detection_job(InputDataConfig=input_data_config, OutputDataConfig=output_data_config, Mode='ONLY_OFFSETS', DataAccessRoleArn=data_access_role,JobName=job_name, LanguageCode='en')
        #print(response)
        #jobId = response["JobId"]
        #print("Job ID is: ", jobId)
        status = ""
        
        if response['JobStatus'] == 'FAILED': 
            print("Job failed")
            logging.error(e)
            sys.exit(e)

        print("Started PII Detection Job:", job_name)
        print("Job Status is: ", response['JobStatus'])
    else: 
        job_name = input_job_name

    # wait for the job to complete
    while True:
        jobs = comprehend.list_pii_entities_detection_jobs(Filter={'JobName': job_name}) 
        # There should be exactly one job item in response
        status = jobs["PiiEntitiesDetectionJobPropertiesList"][0]["JobStatus"]
        jobId = jobs["PiiEntitiesDetectionJobPropertiesList"][0]["JobId"]
        print(status)
        if status != "IN_PROGRESS" and status != 'SUBMITTED':
            break
        time.sleep(60)

    print("Job status is:", status)
    
    #get the location of results 
    if status != 'COMPLETED': 
        print("Something went wrong with the job")
    else: 
        # get the location of results 
        response = comprehend.describe_pii_entities_detection_job(JobId=jobId)
        #print(response)
        result = response["PiiEntitiesDetectionJobProperties"]["OutputDataConfig"]["S3Uri"]
        print("Please check this location for result of analysis: ", result)
        

# Thoughts on extending this... 
# once PII data is found, enable S3 object lock on those objects  

# END OF invoke_comprehend


# START OF invoke_comprehend_for_redaction

def invoke_comprehend_for_redaction(): 
    #print("INSIDE invoke_comprehend_for_redaction")
    comprehend = boto3.client('comprehend', region_name='us-east-1')
    s3 = boto3.client('s3', region_name='us-east-1')
    macie_buc = input('Enter the name of the bucket containing Pii dataset: ')

    # for now, start reading the files in the bucket, find PII data, mask it and print it
    response = s3.list_objects(Bucket=macie_buc)
    #print(response)

    for obj in response['Contents']:
        obj2 =  s3.get_object(Bucket=macie_buc, Key=obj['Key'])
        # print(obj2['ContentType'])
        if( obj2['ContentType'] == 'text/csv' or obj2['ContentType'] == 'text/plain'): 
            print("\n\nAnalyzing file: ", obj['Key'])
            str_buff = obj2['Body'].read().decode('utf-8') 
            #print(str_buff)
            # check if this file has any PII data
            response = comprehend.contains_pii_entities(Text=str_buff, LanguageCode='en')
            #print(response)
            if( response['Labels']): 
                print("\t\tPII data found in this file")
                RedactPiiData(str_buff, response['Labels'])
            else: 
                print("\t\tNo PII data detected in the file")
        else:
            print("Skipping non text file",obj['Key'])

# Thoughts on extending this... 
# once PII data is found, enable S3 object lock on those objects  

# END OF invoke_comprehend

def RedactPiiData( input_text, Labels):
    comprehend = boto3.client('comprehend', region_name='us-east-1')

    # This text has Pii Data as detected by contains_pii_entities() function
    # use detect_pii_entities to get the offset of each of those entities 
    
    response = comprehend.detect_pii_entities(Text=input_text,LanguageCode='en')
    # print(response)
    print("Entities detected: ")
    begin_offset = 0
    end_offset = 0 
    prev_entity = None
    redacted_text = ""
    for entity in response['Entities']: 
        print("\t", entity)
        # mask out Pii entities 
        begin_offset = entity['BeginOffset']
        end_offset = entity['EndOffset']

        if prev_entity is None: 
            redacted_text = input_text[:begin_offset]
        else: 
           redacted_text = redacted_text + input_text[prev_entity['EndOffset']:begin_offset]

        # redact the entry
        entity_length = end_offset - begin_offset 
        redacted_text = redacted_text + ('*' * entity_length) 
        
        prev_entity = entity 
    if prev_entity is not None:
        redacted_text = redacted_text + input_text[prev_entity['EndOffset']:]
    else:
        redacted_text = redacted_text + input_text

    print("\n\n******************Original text:*******************\n\n") 
    print(input_text)
    print("\n\n")
    print("******************Redacted text:*******************\n\n") 
    print(redacted_text)

# This function uses Comprehend to detect Pii entities and shows how to redact Pii entities when via an S3 Object Lambda access point
# you can use S3 Object Lambda to transform the behavior of a GET request

def invoke_comprehend_for_redaction_S3OL(): 
    #print("INSIDE invoke_comprehend_for_redaction_S3OL")
    comprehend = boto3.client('comprehend', region_name='us-east-1')
    s3 = boto3.client('s3', region_name='us-east-1')
    lamb_cl = boto3.client('lambda', region_name='us-east-1')
    macie_buc = input('Enter the name of the bucket containing Pii dataset: ')
    account_id = input('Enter the AWS account ID: ')

    # install an S3 OL access point on the bucket that contains Pii data
    s3_control = boto3.client('s3control', region_name='us-east-1')
    access_point_name = "pii-redactor-access-point1"
    s3_lambda_access_point_name = "s3-ol-access-point1" 

    # create a regular access point first
    response = s3_control.get_access_point(AccountId=account_id, Name=access_point_name)
    if response['Name'] is Empty: 
        print("Creating new access point")
        response = s3_control.create_access_point(AccountId=account_id, Name=access_point_name, Bucket=macie_buc)
        #print(response)
    else: 
        print("Access point is already created")
    access_point_arn = response['AccessPointArn']
    print("Access point Arn: ", access_point_arn)

    # Note that the max duration of an S3 OL function is 60 seconds

    # Also the lambda function needs to have correct permission, there is an AWS managed policy created for it - AmazonS3ObjectLambdaExecutionRolePolicy 
    #   - assign it to an IAM role (along with any S3 policies) and add it as an execution role for lambda
    #   - also it will need permission to access comprehend

    lambda_function_name = "pii_redactor"
    # check if the function exists 
    response = lamb_cl.get_function(FunctionName=lambda_function_name)
    if response['Configuration'] is Empty: 
        print("Please name sure lambda function ", lambda_function_name, " is available in your account.")
        sys.exit("Error")

    lambda_function_arn = "arn:aws:lambda:us-east-1:" + account_id + ":function:" + lambda_function_name
    # check if the S3 OL access point already exists? 
    # Hack, get_access_point_for_object_lambda() does not return the ARN of the function, but get_access_point() does, and ARN is required to call get_object(), so just delete the access point if it exists
    #response = s3_control.get_access_point_for_object_lambda(AccountId=account_id, Name=s3_lambda_access_point_name) 
    #if response['Name'] is not Empty: 
    #    print("Deleting S3 OL access point")
    #    response = s3_control.delete_access_point_for_object_lambda(AccountId=account_id, Name=s3_lambda_access_point_name) 
    # now create the S3 OL access point
    configuration = {
                        "SupportingAccessPoint": access_point_arn, 
                        "CloudWatchMetricsEnabled": True, 
                        "TransformationConfigurations": [
                            {
                                'Actions': [
                                   'GetObject',
                               ],
                               'ContentTransformation': {
                               'AwsLambda': {
                                   'FunctionArn': lambda_function_arn,
                                   'FunctionPayload': ""
                               }
                           }
                        }]
                }
    response = s3_control.create_access_point_for_object_lambda(AccountId=account_id, Name=s3_lambda_access_point_name, Configuration = configuration)
    s3_ol_access_point = response['ObjectLambdaAccessPointArn']
    print("Object lambda access point: ", s3_ol_access_point)

    response = s3.list_objects(Bucket=macie_buc)
    for obj in response['Contents']:
        obj2 =  s3.get_object(Bucket=macie_buc, Key=obj['Key'])
        if( obj2['ContentType'] == 'text/csv' or obj2['ContentType'] == 'text/plain'): 
            print("\n\nAnalyzing file: ", obj['Key'])
            str_buff = obj2['Body'].read().decode('utf-8') 
            print("\n\n******************Original text:*******************\n\n") 
            print(str_buff)
            #access the same object using S3 OL, the lambda function that was installed above will redact the text
            tran_obj = s3.get_object(Bucket=s3_ol_access_point, Key=obj['Key']) 
            str_buff = tran_obj['Body'].read().decode('utf-8') 
            print("******************Redacted text:*******************\n\n") 
            print(str_buff)
        else:
            print("Skipping non text file",obj['Key'])

    print("Deleting S3 OL access point")
    response = s3_control.delete_access_point_for_object_lambda(AccountId=account_id, Name=s3_lambda_access_point_name) 

"""
import json
import requests
import boto3
import logging

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def RedactPiiData( input_text ):
    comprehend = boto3.client('comprehend')

    # This text has Pii Data as detected by contains_pii_entities() function
    # use detect_pii_entities to get the offset of each of those entities 
    
    response = comprehend.detect_pii_entities(Text=input_text,LanguageCode='en')
    # print(response)
    logger.info("Entities detected: ")
    begin_offset = 0
    end_offset = 0 
    prev_entity = None
    redacted_text = ""
    for entity in response['Entities']: 
        logger.info("\t", entity)
        # mask out Pii entities 
        begin_offset = entity['BeginOffset']
        end_offset = entity['EndOffset']

        if prev_entity is None: 
            redacted_text = input_text[:begin_offset]
        else: 
           redacted_text = redacted_text + input_text[prev_entity['EndOffset']:begin_offset]

        # redact the entry
        entity_length = end_offset - begin_offset 
        redacted_text = redacted_text + ('*' * entity_length) 
        
        prev_entity = entity 
    if prev_entity is not None:
        redacted_text = redacted_text + input_text[prev_entity['EndOffset']:]
    else:
        redacted_text = redacted_text + input_text

    return redacted_text
    
def lambda_handler(event, context):
    print(event)

    object_get_context = event["getObjectContext"]
    request_route = object_get_context["outputRoute"]
    request_token = object_get_context["outputToken"]
    s3_url = object_get_context["inputS3Url"]
    
    logger.info(event)
    # Get object from S3
    response = requests.get(s3_url)
    original_object = response.content.decode('utf-8')

    # Transform object
    transformed_object = RedactPiiData(original_object)

    # Write object back to S3 Object Lambda
    s3 = boto3.client('s3')
    s3.write_get_object_response(
        Body=transformed_object,
        RequestRoute=request_route,
        RequestToken=request_token)

    return {'status_code': 200}

# make sure this lambda function is available in your AWS account
"""

# START OF invoke_rekognition

def invoke_rekognition(): 
#    print("INSIDE invoke_rekognition")
    rek_client = boto3.client('rekognition', region_name='us-east-1')
    rekog_buc = input('Enter the name of the bucket containing images to analyze: ')

    print("Analyzing pictures in this S3 bucket: ", rekog_buc) 
    s3_client = boto3.client('s3', region_name='us-east-1')
    response = s3_client.list_objects(Bucket=rekog_buc)
#    print(response) 
    contents = response['Contents']
    print("**********************************")
    str1 = "Number of files in " + rekog_buc + " : " + str(len(contents)) 
    print(str1)
    for x in range(len(contents)):
        print("Analyzing object: ", contents[x]['Key'])  #ok this is the obj name
        resp = rek_client.detect_labels(
            Image={
                'S3Object' : { 
                    'Bucket':rekog_buc, 
                    'Name' : contents[x]['Key'], 
                }, 
            }, 
        )
        print("This object has the following labels: ")
        labels = resp['Labels']
        for y in range(len(labels)): 
            print("Could be \"", labels[y]['Name'], "\", Confidence score: ", labels[y]['Confidence'], " %" )
        # print(resp)
        print("**********************************")

    print("ANALYSIS DONE")

# Thoughts on extending this... 
# once PII data is found, enable S3 object lock on those objects  

# END OF invoke_rekognition

# START OF invoke_kendra

def invoke_kendra(): 

    kendra = boto3.client("kendra", region_name='us-east-1')
    account_id = input('Enter the AWS account ID: ')
    kendra_buc = input('Enter the name of the bucket containing docs to analyze: ')
    
    ans = input("Do you want to create a new index or search for text in one that is created? Press Y for creating a new index or N for searching in one already created\n")
    if ans == "Y": 

        print("Creating a new index")

        description = "Getting started index"
        index_name = "kendra-getting-started-index" + str(random.randint(0,200))
        #Girish: I created the roles in the account, it is a pre-requisite
        index_role_arn = "arn:aws:iam::" + account_id + ":role/KendraRoleForGettingStartedIndex"
        print("Index name", index_name)

        try:
            index_response = kendra.create_index(
                Description = description,
                Name = index_name,
                RoleArn = index_role_arn
            )

            pprint.pprint(index_response)

            index_id = index_response["Id"]

            print("Wait for Kendra to create the index.")

            while True:
                # Get index description
                index_description = kendra.describe_index(
                    Id = index_id
                )
                # When status is not CREATING quit.
                status = index_description["Status"]
                print("    Creating index. Status: "+status)
                time.sleep(60)
                if status != "CREATING":
                    break

            print("Create an S3 data source")

            data_source_name = "python-getting-started-data-source"
            data_source_description = "Getting started data source."
            s3_bucket_name = kendra_buc 
            data_source_type = "S3"
            data_source_role_arn = "arn:aws:iam::" + account_id + ":role/KendraRoleForGettingStartedDataSource"

            configuration = {"S3Configuration":
                {
                    "BucketName": s3_bucket_name
                }
            }

            data_source_response=kendra.create_data_source(
                Configuration = configuration,
                Name = data_source_name,
                Description = description,
                RoleArn = data_source_role_arn,
                Type = data_source_type,

                IndexId = index_id
            )

            pprint.pprint(data_source_response)

            data_source_id = data_source_response["Id"]

            print("Wait for Kendra to create the data source.")

            while True:
                data_source_description = kendra.describe_data_source(
                    Id = data_source_id,
                    IndexId = index_id
                )
                # When status is not CREATING quit.
                status = data_source_description["Status"]
                print("    Creating data source. Status: "+status)
                time.sleep(60)
                if status != "CREATING":
                    break

            print("Synchronize the data source.")

            sync_response = kendra.start_data_source_sync_job(
                Id = data_source_id,
                IndexId = index_id
            )

            pprint.pprint(sync_response)

            print("Wait for the data source to sync with the index.")

            while True:

                jobs = kendra.list_data_source_sync_jobs(
                    Id=data_source_id,
                    IndexId=index_id
                )

                # There should be exactly one job item in response
                status = jobs["History"][0]["Status"]

                print("    Syncing data source. Status: "+status)
                if status != "SYNCING":
                    break
                time.sleep(60)

        except  ClientError as e:
                print("%s" % e)

        print("Kendra index created and sources synced")
    else: 
        #user just wants to query the index 
        query=input("Enter the search string: ") 
        #there could be multiple indices .. which one will the user want to use? 

        response = kendra.list_indices()
        # print(response)
        list_indices = response['IndexConfigurationSummaryItems']
        y = 1
        for x in range(len(list_indices)): 
            print("Index #: ", y)
            print("Index name: ", list_indices[x]['Name']) 
            print("Index Id: ", list_indices[x]['Id']) 
            y = y + 1 
                
        index_to_use = int(input("Which index do you want to use?\n "))
        print("Index chosen for this query: Name: \"", list_indices[index_to_use-1]['Name'], "\" Id: \"", list_indices[index_to_use-1]['Id'], "\"\n")
        index_id = list_indices[index_to_use-1]['Id'] 

        response=kendra.query(
            QueryText = query,
            IndexId = index_id)

        print ('\nSearch results for query: ' + query + '\n')        

        for query_result in response['ResultItems']:

            print('-------------------')
            print('Type: ' + str(query_result['Type']))
        
            if query_result['Type']=='ANSWER' or query_result['Type'] == 'QUESTION_ANSWER':
                answer_text = query_result['DocumentExcerpt']['Text']
                print(answer_text)

        if query_result['Type']=='DOCUMENT':
            if 'DocumentTitle' in query_result:
                document_title = query_result['DocumentTitle']['Text']
                print('Title: ' + document_title)
            print('Document: ', query_result['DocumentURI']) 
            document_text = query_result['DocumentExcerpt']['Text']
            print(document_text)

        print ('------------------\n\n')  

# END OF invoke_kendra



# START OF main

if __name__ == '__main__':
    print('')
    print('')
    print("         DATA ANALYSIS PROGRAM")
    print('')
    print('')
    choice = input("What type of analysis do you want to do today?\n\nOPTIONS\n\n"
                    "1. PII detection using Amazon Macie\n"
                    "2. PII detection using Amazon Comprehend\n"
                    "3. PII detection and redaction using Amazon Comprehend\n"
                    "4. PII detection and redaction using Amazon Comprehend and S3 Object Lambda\n"
                    "5. Analyze Images using Amazon Rekognition\n"
                    "6. Index docs and search using Amazon Kendra\n\nEnter choice:")
    if choice == "1": 
        invoke_macie()
    elif choice == "2": 
        invoke_comprehend()
    elif choice == "3":
        invoke_comprehend_for_redaction()
    elif choice == "4": 
        invoke_comprehend_for_redaction_S3OL()
    elif choice == "5": 
        invoke_rekognition()
    elif choice == '6': 
        invoke_kendra()
    else: 
        print("Exiting..")
        
# END OF main