FINDINGS = {
    "Findings": [
        {
            "Resource": {
                "AccessKeyDetails": {
                    "UserName": "testuser",
                    "UserType": "IAMUser",
                    "PrincipalId": "AIDACKCEVSQ6C2EXAMPLE",
                    "AccessKeyId": "ASIASZ4SI7REEEXAMPLE"
                },
                'InstanceDetails': {
                    'AvailabilityZone': 'string',
                    'IamInstanceProfile': {
                        'Arn': 'string',
                        'Id': 'string'
                    },
                    'ImageDescription': 'string',
                    'ImageId': 'string',
                    'InstanceId': 'string',
                    'InstanceState': 'string',
                    'InstanceType': 'string',
                    'OutpostArn': 'string',
                    'LaunchTime': 'string',
                    'NetworkInterfaces': [
                        {
                            'Ipv6Addresses': [
                                'string',
                            ],
                            'NetworkInterfaceId': 'string',
                            'PrivateDnsName': 'string',
                            'PrivateIpAddress': 'string',
                            'PrivateIpAddresses': [
                                {
                                    'PrivateDnsName': 'string',
                                    'PrivateIpAddress': 'string'
                                },
                            ],
                            'PublicDnsName': 'string',
                            'PublicIp': 'string',
                            'SecurityGroups': [
                                {
                                    'GroupId': 'string',
                                    'GroupName': 'string'
                                },
                            ],
                            'SubnetId': 'string',
                            'VpcId': 'string'
                        },
                    ],
                    'Platform': 'string',
                    'ProductCodes': [
                        {
                            'Code': 'string',
                            'ProductType': 'string'
                        },
                    ],
                    'Tags': [
                        {
                            'Key': 'string',
                            'Value': 'string'
                        },
                    ]
                },
            },
            "Description": "APIs commonly used to discover the users, groups, policies and permissions in an account, was invoked by IAM principal testuser under unusual circumstances. Such activity is not typically seen from this principal.",
            "Service": {
                "Count": 5,
                "Archived": False,
                "ServiceName": "guardduty",
                "EventFirstSeen": "2020-05-26T22:02:24Z",
                "ResourceRole": "TARGET",
                "EventLastSeen": "2020-05-26T22:33:55Z",
                "DetectorId": "d4b040365221be2b54a6264dcexample",
                "Action": {
                    "ActionType": "AWS_API_CALL",
                    "AwsApiCallAction": {
                        "RemoteIpDetails": {
                            "GeoLocation": {
                                "Lat": 51.5164,
                                "Lon": -0.093
                            },
                            "City": {
                                "CityName": "London"
                            },
                            "IpAddressV4": "52.94.36.7",
                            "Organization": {
                                "Org": "Amazon.com",
                                "Isp": "Amazon.com",
                                "Asn": "16509",
                                "AsnOrg": "AMAZON-02"
                            },
                            "Country": {
                                "CountryName": "United Kingdom"
                            }
                        },
                        "Api": "ListPolicyVersions",
                        "ServiceName": "iam.amazonaws.com",
                        "CallerType": "Remote IP"
                    }
                }
            },
            "Title": "Unusual user permission reconnaissance activity by testuser.",
            "Type": "Recon:IAMUser/UserPermissions",
            "Region": "us-east-1",
            "Partition": "aws",
            "Arn": "arn:aws:guardduty:us-east-1:111122223333:detector/d4b040365221be2b54a6264dcexample/finding/1ab92989eaf0e742df4a014d5example",
            "UpdatedAt": "2020-05-26T22:55:21.703Z",
            "SchemaVersion": "2.0",
            "Severity": 5,
            "Id": "f-01",
            "CreatedAt": "2020-05-26T22:21:48.385Z",
            "AccountId": "111122223333"
        }
    ]
}