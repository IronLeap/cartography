import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple

import boto3
import neo4j

from cartography.util import aws_handle_regions
from cartography.util import aws_paginate
from cartography.util import batch
from cartography.util import run_cleanup_job
from cartography.util import timeit


logger = logging.getLogger(__name__)


@timeit
@aws_handle_regions
def get_inspector_findings(
    session: boto3.session.Session,
    region: str,
    current_aws_account_id: str,
) -> List[Dict]:
    '''
    We must list_findings by filtering the request, otherwise the request could tiemout.
    First, we filter by account_id. And since there may be millions of CLOSED findings that may never go away,
    we will only fetch those in ACTIVE or SUPPRESSED statuses.
    list_members will get us all the accounts that
    have delegated access to the account specified by current_aws_account_id.
    '''
    client = session.client('inspector2', region_name=region)

    members = aws_paginate(client, 'list_members', 'members')
    # the current host account may not be considered a "member", but we still fetch its findings
    accounts = [current_aws_account_id] + [m['accountId'] for m in members]

    findings = []
    for account in accounts:
        logger.info(f'Getting findings for member account {account} in region {region}')
        findings.extend(
            aws_paginate(
                client, 'list_findings', 'findings', filterCriteria={
                    'awsAccountId': [
                        {
                            'comparison': 'EQUALS',
                            'value': account,
                        },
                    ],
                    'findingStatus': [
                        {
                            'comparison': 'NOT_EQUALS',
                            'value': 'CLOSED',
                        },
                    ],
                },
            ),
        )
    return findings


def transform_inspector_findings(results: List[Dict]) -> Tuple[List, List]:
    findings_list: List[Dict] = []
    packages: Dict[str, Any] = {}

    for f in results:
        finding: Dict = {}

        finding['id'] = f['findingArn']
        finding['arn'] = f['findingArn']
        finding['severity'] = f['severity'].lower()
        finding['name'] = f['title']
        finding['firstobservedat'] = f['firstObservedAt']
        finding['awsaccount'] = f['awsAccountId']
        finding['description'] = f['description']
        finding['type'] = f['type']
        finding['status'] = f['status']
        if f.get('inspectorScoreDetails'):
            finding['cvssscore'] = f['inspectorScoreDetails']['adjustedCvss']['score']
        finding["resources"] = []
        for resource in f["resources"]:
            resourceDic: Dict={"type": resource["type"]}

            if resource['type'] == "AWS_EC2_INSTANCE":
                resourceDic["instanceid"] = resource['id']
            elif resource['type'] == "AWS_ECR_CONTAINER_IMAGE":
                resourceDic['ecrimageid'] = resource['id']
            elif resource['type'] == "AWS_ECR_REPOSITORY":
                resourceDic['ecrrepositoryid'] = resource['id']
            elif resource['type'] == "AWS_LAMBDA_FUNCTION":
                resourceDic['lambdaid'] = resource['id']
            finding["resources"].append(resourceDic)
        if f.get('networkReachabilityDetails'):
            finding['protocol'] = f['networkReachabilityDetails']['protocol']
            finding['portrangebegin'] = f['networkReachabilityDetails']['openPortRange']['begin']
            finding['portrangeend'] = f['networkReachabilityDetails']['openPortRange']['end']
        if f.get('packageVulnerabilityDetails'):
            finding['vulnerabilityid'] = f['packageVulnerabilityDetails']['vulnerabilityId']
            finding['referenceurls'] = f['packageVulnerabilityDetails'].get('referenceUrls')
            new_packages = _process_packages(f['packageVulnerabilityDetails'], f['findingArn'])
            finding['vulnerablepackageids'] = list(new_packages.keys())
            packages = {**packages, **new_packages}

        findings_list.append(finding)
    packages_list = transform_inspector_packages(packages)
    return findings_list, packages_list


def transform_inspector_packages(packages: Dict[str, Any]) -> List[Dict]:
    packages_list: List[Dict] = []
    for package_id in packages.keys():
        packages_list.append(packages[package_id])

    return packages_list


def _process_packages(package_details: Dict[str, Any], finding_arn: str) -> Dict[str, Any]:
    packages: Dict[str, Any] = {}
    for package in package_details['vulnerablePackages']:
        new_package = {}
        new_package['id'] = (
            f"{package.get('name', '')}|"
            f"{package.get('arch', '')}|"
            f"{package.get('version', '')}|"
            f"{package.get('release', '')}|"
            f"{package.get('epoch', '')}"
        )
        new_package['name'] = package.get('name')
        new_package['arch'] = package.get('arch')
        new_package['version'] = package.get('version')
        new_package['release'] = package.get('release')
        new_package['epoch'] = package.get('epoch')
        new_package['manager'] = package.get("packageManager")
        new_package['filepath'] = package.get('filePath')
        new_package['fixedinversion'] = package.get('fixedInVersion')
        new_package['sourcelayerhash'] = package.get('sourceLayerHash')
        new_package['findingarn'] = finding_arn

        packages[new_package['id']] = new_package

    return packages


def _port_range_string(details: Dict) -> str:
    begin = details['openPortRange']['begin']
    end = details['openPortRange']['end']
    return f"{begin}-{end}"


def _load_findings_tx(
    tx: neo4j.Transaction,
    findings: List[Dict],
    region: str,
    aws_update_tag: int,
) -> None:
    ingest_findings = """
    UNWIND $Findings as new_finding
        MERGE (finding:AWSInspectorFinding{id: new_finding.id})
        ON CREATE SET finding.firstseen = timestamp(),
            finding.arn = new_finding.arn,
            finding.region = $Region,
            finding.awsaccount = new_finding.awsaccount
        SET finding.lastupdated = $UpdateTag,
            finding.name = new_finding.title,
            finding.severity = new_finding.severity,
            finding.firstobservedat = new_finding.firstobservedat,
            finding.description = new_finding.description,
            finding.type = new_finding.type,
            finding.cvssscore = new_finding.cvssscore,
            finding.protocol = new_finding.protocol,
            finding.portrangebegin = new_finding.portrangebegin,
            finding.portrangeend = new_finding.portrangeend,
            finding.vulnerabilityid = new_finding.vulnerabilityid,
            finding.referenceurls = new_finding.referenceurls,
            finding.relatedvulnerabilities = new_finding.relatedvulnerabilities,
            finding.status = new_finding.status,
            finding.vulnerablepackageids = new_finding.vulnerablepackageids
        WITH finding, new_finding
        FOREACH (x in CASE WHEN finding.type = "NETWORK_REACHABILITY" THEN [1] ELSE [] END | 
        SET finding:OpenNetwork
        )
        FOREACH (x in CASE WHEN finding.type = "PACKAGE_VULNERABILITY" THEN [1] ELSE [] END | 
        SET finding:CVE
        )
         WITH finding, new_finding
        MATCH (account:AWSAccount{id: finding.awsaccount})
        MERGE (account)-[r:RESOURCE]->(finding)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $UpdateTag
        WITH finding, new_finding
        UNWIND new_finding.resources as resource
        WITH finding,resource
        WHERE resource.type = "AWS_EC2_INSTANCE"
        MATCH (instance:EC2Instance{id: resource.instanceid})
        WITH instance,finding
        FOREACH (x in CASE WHEN finding.type = "NETWORK_REACHABILITY" THEN [1] ELSE [] END | 
        MERGE (instance)-[r2:HAS_OPEN_NETWORK]->(finding) 
        ON CREATE SET r2.firstseen = timestamp() 
        SET r2.lastupdated = $UpdateTag, finding:OpenNetwork
        )
        FOREACH (x in CASE WHEN finding.type = "PACKAGE_VULNERABILITY" THEN [1] ELSE [] END | 
        MERGE (instance)-[r2:HAS_VULNERABILITY]->(finding) 
        ON CREATE SET r2.firstseen = timestamp() 
        SET r2.lastupdated = $UpdateTag, finding:CVE
        )
    """

    tx.run(
        ingest_findings,
        Findings=findings,
        UpdateTag=aws_update_tag,
        Region=region,
    )



@timeit
def load_inspector_findings(
    neo4j_session: neo4j.Session, findings: List[Dict], region: str,
    aws_update_tag: int,
) -> None:
    for i, findings_batch in enumerate(batch(findings), start=1):
        logger.info(f'Loading batch number {i}')
        neo4j_session.write_transaction(
            _load_findings_tx,
            findings=findings_batch,
            region=region,
            aws_update_tag=aws_update_tag,
        )


def _load_packages_tx(
    tx: neo4j.Transaction,
    packages: List[Dict],
    region: str,
    aws_update_tag: int,
) -> None:
    query = """
    UNWIND $Packages as new_package
        MERGE (package:AWSInspectorPackage{id: new_package.id})
        ON CREATE SET package.firstseen = timestamp()
        SET package.lastupdated = $UpdateTag,
            package.name = new_package.name,
            package.arch = new_package.arch,
            package.version = new_package.version,
            package.release = new_package.release,
            package.epoch = new_package.epoch,
            package.manager = new_package.packageManager,
            package.filepath = new_package.filePath,
            package.fixedinversion = new_package.fixedInVersion,
            package.sourcelayerhash = new_package.sourceLayerHash
        WITH package
        MATCH (finding:AWSInspectorFinding{id: package.findingarn})
        MERGE (finding)-[r:HAS]->(package)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $UpdateTag
    """

    tx.run(
        query,
        Packages=packages,
        UpdateTag=aws_update_tag,
        Region=region,
    )


@timeit
def load_inspector_packages(
    neo4j_session: neo4j.Session, packages: List[Dict], region: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.write_transaction(
        _load_packages_tx,
        packages=packages,
        region=region,
        aws_update_tag=aws_update_tag,
    )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_inspector_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.session.Session,
    regions: List[str],
    current_aws_account_id: str,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    for region in regions:
        logger.info(f"Syncing AWS Inspector findings for account {current_aws_account_id} and region {region}")
        findings = get_inspector_findings(boto3_session, region, current_aws_account_id)
        finding_data, package_data = transform_inspector_findings(findings)
        logger.info(f"Loading {len(finding_data)} findings")
        load_inspector_findings(neo4j_session, finding_data, region, update_tag)
        logger.info(f"Loading {len(package_data)} packages")
        load_inspector_packages(neo4j_session, package_data, region, update_tag)
        cleanup(neo4j_session, common_job_parameters)
