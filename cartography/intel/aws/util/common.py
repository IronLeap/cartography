import json
from typing import Dict
from typing import List

from cartography.intel.aws.resources import RESOURCE_FUNCTIONS


def parse_and_validate_aws_requested_syncs(aws_requested_syncs: str) -> List[str]:
    validated_resources: List[str] = []
    for resource in aws_requested_syncs.split(','):
        resource = resource.strip()

        if resource in RESOURCE_FUNCTIONS:
            validated_resources.append(resource)
        else:
            valid_syncs: str = ', '.join(RESOURCE_FUNCTIONS.keys())
            raise ValueError(
                f'Error parsing `aws-requested-syncs`. You specified "{aws_requested_syncs}". '
                f'Please check that your string is formatted properly. '
                f'Example valid input looks like "s3,iam,rds" or "s3, ec2:instance, dynamodb". '
                f'Our full list of valid values is: {valid_syncs}.',
            )
    return validated_resources


def parse_and_validate_aws_custom_sync_profile(aws_custom_sync_profile: str) -> Dict[str, str]:
    aws_custom_sync_profile_dct = json.loads(aws_custom_sync_profile)

    # account_name is mandatory
    if 'account_name' not in aws_custom_sync_profile_dct:
        raise ValueError('Error parsing aws_custom_sync_profile. No valid account_name.')
    account_name = aws_custom_sync_profile_dct['account_name']
    if type(account_name) != str or len(account_name) == 0:
        raise ValueError(
            'Error parsing aws_custom_sync_profile. account_name should be a valid string.',
        )
    
    # vulnerability_scan is mandatory
    if 'vulnerability_scan' not in aws_custom_sync_profile_dct:
        raise ValueError('Error parsing aws_custom_sync_profile. No valid vulnerability_scan.')
    vulnerability_scan = aws_custom_sync_profile_dct['vulnerability_scan']
    if type(vulnerability_scan) != str or len(vulnerability_scan) == 0:
        raise ValueError(
            'Error parsing aws_custom_sync_profile. vulnerability_scan should be a valid string.',
        )

    # If profile present, it's sufficient to validate it
    if 'profile' in aws_custom_sync_profile_dct:
        profile = aws_custom_sync_profile_dct['profile']
        if type(profile) != str or len(profile) == 0:
            raise ValueError(
                'Error parsing aws_custom_sync_profile. profile should be a valid string.',
            )
        return aws_custom_sync_profile_dct
    
    if 'region_names' not in aws_custom_sync_profile_dct:
         raise ValueError('Error parsing aws_custom_sync_profile. No valid region_names paramter.')
    region_names = aws_custom_sync_profile_dct['region_names']
    if type(region_names) != List[str]:
        raise ValueError(
        'Error parsing aws_custom_sync_profile. region_names should be a valid list of strings.',
    )

    # Otherwise, must validate aws_access_key_id and aws_secret_access_key
    for key in ['aws_access_key_id', 'aws_secret_access_key']:
        if key not in aws_custom_sync_profile_dct:
            raise ValueError(f'Error parsing aws_custom_sync_profile. No valid {key}.')
        value = aws_custom_sync_profile_dct[key]
        if type(value) != str or len(value) == 0:
            raise ValueError(
                f'Error parsing aws_custom_sync_profile. {key} should be a valid string.',
            )
    return aws_custom_sync_profile_dct
