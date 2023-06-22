import logging
import time
from datetime import datetime
from typing import Any
from typing import Dict
from typing import List

import boto3
import neo4j

from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
@aws_handle_regions
def get_guardduty_findings(boto3_session: boto3.session.Session) -> List[Dict]:
    client = boto3_session.client('guardduty')
    # paginator = client.get_paginator('get_findings')
    detectorResponse = client.list_detectors()
    detectorIds = detectorResponse['DetectorIds']

    findingsList = []
    for detectorId in detectorIds:
        list_finding_params = {
            'DetectorId': detectorId
        }
        findingIdsResponse = client.list_findings(**list_finding_params)
        findingIds = findingIdsResponse["FindingIds"]

        get_findings_params = {
            'DetectorId': detectorId,
            'FindingIds':findingIds
        }
        findings: List[Dict] 
        findingsResponse = client.get_findings(**get_findings_params)
        findings=findingsResponse['Findings']

        findingsList.append(findings)
    
    return findingsList


@timeit
def load_guardduty_findings(
    neo4j_session: neo4j.Session, findingsList: List[List[Dict]], current_aws_account_id: str, aws_update_tag: int,
) -> None:
    
    ingest_findings = """
    UNWIND $Findings as finding
    WITH finding
    WHERE EXISTS(finding.Resource.InstanceDetails)
    MERGE (f:GuardDutyFinding {arn: finding.Arn})
    ON CREATE SET f.firstseen = timestamp()
    SET f.lastupdated = $update_tag,
    f.id = finding.Id,
    f.severity = finding.Severity,
    f.title = finding.Title,
    f.type = finding.Type,
    f.created_at = finding.CreatedAt,
    f.description = finding.Description
    WITH f,finding
    MATCH (a:AWSAccount {id: $AccountId})
    MERGE (a)-[r_af:RESOURCE]->(f)
    ON CREATE SET r_af.firstseen = timestamp()
    SET r_af.lastupdated = $update_tag
    WITH f,finding
    MERGE (ec2:EC2Instance {instanceid:finding.Resource.InstanceDetails.InstanceId})
    ON CREATE SET ec2.firstseen = timestamp()
    SET ec2.lastupdated = $update_tag
    WITH f,ec2
    MERGE (f)-[r_fr:ASSOCIATED_RESOURCE]->(ec2)
    ON CREATE SET r_fr.firstseen = timestamp()
    SET r_fr.lastupdated = $update_tag
        
    """

    for findings in findingsList:

        neo4j_session.run(
            ingest_findings,
            Findings = findings,
            AccountId=current_aws_account_id,
            update_tag=aws_update_tag
        )

@timeit
def cleanup_guardduty_findings(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_ingest_guardduty_findings_cleanup.json', neo4j_session, common_job_parameters)



@timeit
def sync(
        neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str],
        current_aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    logger.info("Syncing guard duty findings for account '%s'.",current_aws_account_id)
    data = get_guardduty_findings(boto3_session)
    load_guardduty_findings(neo4j_session, data, current_aws_account_id, update_tag)
    cleanup_guardduty_findings(neo4j_session, common_job_parameters)