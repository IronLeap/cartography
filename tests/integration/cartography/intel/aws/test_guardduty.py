import tests.data.aws.guardduty
import cartography.intel.aws.guardduty

TEST_ACCOUNT_ID = '000000000000'
TEST_UPDATE_TAG = 123456789

def test_load_guardduty_findings(neo4j_session, *args):
    dataList = []
    data = tests.data.aws.guardduty.FINDINGS['Findings']
    dataList.append(data)
    cartography.intel.aws.guardduty.load_guardduty_findings(
        neo4j_session,dataList,TEST_ACCOUNT_ID,TEST_UPDATE_TAG
    )

    expected_nodes = {
        "f-01"
    }

    nodes = neo4j_session.run(
        """
        MATCH (f:GuardDutyFinding) return f.id
        """
    )

    actual_nodes = {
        n['f.id']
        for n in nodes
    }

    assert actual_nodes == expected_nodes
