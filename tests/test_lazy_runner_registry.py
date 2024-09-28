from checkov.ansible.runner import Runner as ansible_runner
from checkov.argo_workflows.runner import Runner as argo_workflows_runner
from checkov.arm.runner import Runner as arm_runner
from checkov.azure_pipelines.runner import Runner as azure_pipelines_runner
from checkov.bicep.runner import Runner as bicep_runner
from checkov.bitbucket.runner import Runner as bitbucket_configuration_runner
from checkov.bitbucket_pipelines.runner import Runner as bitbucket_pipelines_runner
from checkov.cdk.runner import CdkRunner
from checkov.circleci_pipelines.runner import Runner as circleci_pipelines_runner
from checkov.cloudformation.runner import Runner as cfn_runner
from checkov.common.bridgecrew.check_type import CheckType, checkov_runners, sast_types
from checkov.dockerfile.runner import Runner as dockerfile_runner
from checkov.github.runner import Runner as github_configuration_runner
from checkov.github_actions.runner import Runner as github_actions_runner
from checkov.gitlab.runner import Runner as gitlab_configuration_runner
from checkov.gitlab_ci.runner import Runner as gitlab_ci_runner
from checkov.helm.runner import Runner as helm_runner
from checkov.json_doc.runner import Runner as json_runner
from checkov.kubernetes.runner import Runner as k8_runner
from checkov.kustomize.runner import Runner as kustomize_runner
from checkov.lazy_runner_registry import LAZY_DEFAULT_RUNNERS
from checkov.openapi.runner import Runner as openapi_runner
from checkov.sast.runner import Runner as sast_runner
from checkov.sca_package_2.runner import Runner as sca_package_runner_2
from checkov.sca_image.runner import Runner as sca_image_runner
from checkov.secrets.runner import Runner as secrets_runner
from checkov.serverless.runner import Runner as sls_runner
from checkov.terraform.plan_runner import Runner as tf_plan_runner
from checkov.terraform.runner import Runner as tf_graph_runner
from checkov.terraform_json.runner import TerraformJsonRunner
from checkov.yaml_doc.runner import Runner as yaml_runner

import pytest

expected_runner_types = sorted(set(checkov_runners) - set(sast_types) - {CheckType.POLICY_3D})

type_to_runner = {
    CheckType.ANSIBLE: ansible_runner,
    CheckType.ARGO_WORKFLOWS: argo_workflows_runner,
    CheckType.ARM: arm_runner,
    CheckType.AZURE_PIPELINES: azure_pipelines_runner,
    CheckType.BICEP: bicep_runner,
    CheckType.BITBUCKET_PIPELINES: bitbucket_pipelines_runner,
    CheckType.CDK: CdkRunner,
    CheckType.CIRCLECI_PIPELINES: circleci_pipelines_runner,
    CheckType.CLOUDFORMATION: cfn_runner,
    CheckType.DOCKERFILE: dockerfile_runner,
    CheckType.GITHUB_CONFIGURATION: github_configuration_runner,
    CheckType.GITHUB_ACTIONS: github_actions_runner,
    CheckType.GITLAB_CONFIGURATION: gitlab_configuration_runner,
    CheckType.GITLAB_CI: gitlab_ci_runner,
    CheckType.BITBUCKET_CONFIGURATION: bitbucket_configuration_runner,
    CheckType.HELM: helm_runner,
    CheckType.JSON: json_runner,
    CheckType.YAML: yaml_runner,
    CheckType.KUBERNETES: k8_runner,
    CheckType.KUSTOMIZE: kustomize_runner,
    CheckType.OPENAPI: openapi_runner,
    CheckType.SCA_PACKAGE: sca_package_runner_2,
    CheckType.SCA_IMAGE: sca_image_runner,
    CheckType.SECRETS: secrets_runner,
    CheckType.SERVERLESS: sls_runner,
    CheckType.TERRAFORM: tf_graph_runner,
    CheckType.TERRAFORM_JSON: TerraformJsonRunner,
    CheckType.TERRAFORM_PLAN: tf_plan_runner,
    CheckType.SAST: sast_runner,
}

type_to_lazy_runner = {lazy_runner.check_type: lazy_runner for lazy_runner in LAZY_DEFAULT_RUNNERS}

def test_lazy_default_runners_complete():
    assert expected_runner_types == sorted(type_to_lazy_runner) == sorted(type_to_runner)

def test_lazy_default_runners_no_duplicates():
    # Ensure that there is one and only one lazy runner for each check type
    assert len(LAZY_DEFAULT_RUNNERS) == len(type_to_lazy_runner)

@pytest.mark.parametrize("check_type", expected_runner_types)
def test_lazy_default_runners_load_class(check_type: CheckType):
    lazy_runner = type_to_lazy_runner[check_type]
    eager_runner = type_to_runner[check_type]
    # Perform identity ('x is y') comparison to ensure that the correct class is loaded
    assert lazy_runner.load_runner_class() is eager_runner
