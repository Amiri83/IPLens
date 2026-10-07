import pytest

from iplens.attribution import attribute_eni


@pytest.mark.parametrize("eni, owner, ref", [
    ({"InterfaceType": "nat_gateway", "Description": "Interface for NAT Gateway nat-0abc123"},
     "nat", "nat-0abc123"),
    ({"InterfaceType": "vpc_endpoint", "Description": "VPC Endpoint Interface vpce-0abc123"},
     "vpc_endpoint", "vpce-0abc123"),
    ({"InterfaceType": "lambda", "Description": "AWS Lambda VPC ENI-example-fn"},
     "lambda", "example-fn"),
    ({"InterfaceType": "interface", "RequesterId": "123456789012:awslambda_example",
      "Description": "AWS Lambda VPC ENI-example-fn-1a2b3c4d-1111-2222-3333-aaaabbbbcccc"},
     "lambda", "example-fn"),
    ({"InterfaceType": "network_load_balancer", "Description": "ELB net/example-nlb/0123abcd"},
     "elb", "example-nlb"),
    ({"InterfaceType": "interface", "RequesterId": "amazon-elb", "RequesterManaged": True,
      "Description": "ELB app/example-alb/0123abcd"}, "elb", "example-alb"),
    ({"Description": "ELB example-classic"}, "elb", "example-classic"),
    ({"InterfaceType": "interface", "RequesterId": "amazon-rds", "RequesterManaged": True,
      "Description": "RDSNetworkInterface"}, "rds", ""),
    ({"InterfaceType": "interface", "Description": "",
      "Attachment": {"InstanceId": "i-0example0001"}}, "ec2", "i-0example0001"),
    ({"InterfaceType": "trunk", "Attachment": {"InstanceId": "i-0example0002"}},
     "ec2", "i-0example0002"),
    ({"InterfaceType": "interface", "Description": "EFS mount target for fs-0example"},
     "other", "EFS"),
    ({"InterfaceType": "transit_gateway"}, "other", "transit_gateway"),
    ({"InterfaceType": "interface", "Description": "example detached"}, "other", ""),
])
def test_attribution(eni, owner, ref):
    a = attribute_eni(eni)
    assert (a.owner_type, a.owner_ref) == (owner, ref)
