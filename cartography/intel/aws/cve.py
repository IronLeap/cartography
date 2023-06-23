import boto3
from cartography.util import run_cleanup_job
import neo4j
import logging
import json
import subprocess
import yaml

from typing import Any
from typing import Dict
from typing import List

from cartography.util import timeit


logger = logging.getLogger(__name__)

# templateFileNames = ["dns/ptr-fingerprint.yaml","dns/cname-fingerprint.yaml","dns/ec2-detection.yaml"]
# templateFileNamesStr = "dns/ptr-fingerprint.yaml,dns/cname-fingerprint.yaml,dns/ec2-detection.yaml"
templateFileNames = ["http/cves/2022/CVE-2022-42233.yaml","http/cves/2023/CVE-2023-27179.yaml","http/cves/2022/CVE-2022-45933.yaml","http/cves/2023/CVE-2023-1020.yaml","http/cves/2023/CVE-2023-1177.yaml","http/cves/2023/CVE-2023-1671.yaml","http/cves/2023/CVE-2023-20864.yaml","http/cves/2023/CVE-2023-23488.yaml","http/cves/2023/CVE-2023-23489.yaml","http/cves/2023/CVE-2023-25135.yaml"]
templateFileNamesStr = "http/cves/2022/CVE-2022-42233.yaml,http/cves/2023/CVE-2023-27179.yaml,http/cves/2022/CVE-2022-45933.yaml,http/cves/2023/CVE-2023-1020.yaml,http/cves/2023/CVE-2023-1177.yaml,http/cves/2023/CVE-2023-1671.yaml,http/cves/2023/CVE-2023-20864.yaml,http/cves/2023/CVE-2023-23488.yaml,http/cves/2023/CVE-2023-23489.yaml,http/cves/2023/CVE-2023-25135.yaml"

@timeit
def load_cves(neo4j_session: neo4j.Session,aws_update_tag:int,current_aws_account_id:str)->None:
    publicly_exposed_query = """
    OPTIONAL MATCH (:AWSAccount{id:$AccountId})-[:RESOURCE]->(ec2:EC2Instance) where ec2.publicipaddress is not null
    WITH collect({
        id: ID(ec2),
        publicDnsOrIp: ec2.publicipaddress,
        resourceType: "EC2Instance"
    })  as ec2Info
    OPTIONAL MATCH (:AWSAccount{id:$AccountId})-[:RESOURCE]->(rds:RDSInstance {publicly_accessible:true})
    WITH collect({
        id: ID(rds),
        publicDnsOrIp: rds.endpoint_address,
        resourceType: "RDSInstance"
    })  as rdsInfo,ec2Info
    OPTIONAL MATCH (:AWSAccount{id:$AccountId})-[:RESOURCE]->(lbv2:LoadBalancerV2 {scheme:"internet-facing"})  
    WITH collect({
        id: ID(lbv2),
        publicDnsOrIp: lbv2.dnsname,
        resourceType: "LoadBalancerV2"
    })  as lbv2Info,rdsInfo,ec2Info
    WITH ec2Info + rdsInfo + lbv2Info as publiclyExposedResources
    return publiclyExposedResources
    """

    ingest_cve = """
    UNWIND $CVEResults as cve_result
    MERGE (cve:CVE {template_id:cve_result.`template-id`})
    ON CREATE SET cve.firstseen = timestamp()
    SET cve.name=cve_result.info.name,
    cve.cvss_score=cve_result.classification.`cvss-score`,
    cve.template_link=cve_result.`template-url`, 
    cve.severity=cve_result.info.severity, 
    cve.description=cve_result.info.description,
    cve.lastupdated = $aws_update_tag
    WITH cve,cve_result
    MATCH (rnode) where ID(rnode)=$NodeId
    MERGE (rnode)-[r:HAS_VULNERABILITY]->(cve)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag,
    r.extracted_results=cve_result.`extracted-results`,
    r.matched_at=cve_result.`matched-at`
    """

    records = neo4j_session.run(
        publicly_exposed_query,
        AccountId=current_aws_account_id
    )

    for record in records:
        for resource in record["publiclyExposedResources"]:
            if (
                "publicDnsOrIp" not in resource 
                or "id" not in resource 
                or resource['publicDnsOrIp']==None 
                or resource['publicDnsOrIp']==""
            ):
                continue
            
            logger.info(f"Syncing CVE for resource: {resource['publicDnsOrIp']}")

            cmd = f"nuclei -t {templateFileNamesStr} -silent -u http://{resource['publicDnsOrIp']}/ -jsonl"
            
            output = subprocess.check_output(cmd, shell=True)

            # Split the output into lines and parse each line as a separate JSON object
            scanResults = []
            for line in output.splitlines():
                decoded_line = line.decode()
                if decoded_line:
                    scanResults.append(json.loads(decoded_line))
            
            neo4j_session.run(
                ingest_cve,
                NodeId=resource["id"],
                CVEResults=scanResults,
                aws_update_tag=aws_update_tag,
            )

@timeit
def cleanup_cves(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_ingest_cves_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
        neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str],
        current_aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    logger.info("Syncing CVES for account '%s'",current_aws_account_id)

    load_cves(neo4j_session,update_tag,current_aws_account_id)
    cleanup_cves(neo4j_session, common_job_parameters)

