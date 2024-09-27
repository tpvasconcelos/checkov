from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast
from importlib import import_module

from checkov.common.bridgecrew.check_type import CheckType

if TYPE_CHECKING:
    from checkov.common.runners.base_runner import BaseRunner

@dataclass
class LazyRunner:
    check_type: CheckType
    module: str | None = None
    cls: str = "Runner"

    def __post_init__(self):
        inferred_module_qualname = f"checkov.{self.check_type}.runner"
        if self.module == inferred_module_qualname:
            raise ValueError(f"Redundant module name provided for {self!r}.")
        if self.module is None:
            self.module = inferred_module_qualname

    def load_runner_class(self) -> type[BaseRunner]:
        module = import_module(self.module)
        return getattr(module, self.cls)

    def load_runner(self) -> BaseRunner:
        return self.load_runner_class()()


# sca package runner added during the run method
LAZY_DEFAULT_RUNNERS: "list[LazyRunner]" = [
    LazyRunner(check_type=CheckType.ANSIBLE),
    LazyRunner(check_type=CheckType.ARGO_WORKFLOWS),
    LazyRunner(check_type=CheckType.ARM),
    LazyRunner(check_type=CheckType.AZURE_PIPELINES),
    LazyRunner(check_type=CheckType.BICEP),
    LazyRunner(check_type=CheckType.BITBUCKET_CONFIGURATION, module="checkov.bitbucket.runner"),
    LazyRunner(check_type=CheckType.BITBUCKET_PIPELINES),
    LazyRunner(check_type=CheckType.CDK, cls="CdkRunner"),
    LazyRunner(check_type=CheckType.CIRCLECI_PIPELINES),
    LazyRunner(check_type=CheckType.CLOUDFORMATION),
    LazyRunner(check_type=CheckType.DOCKERFILE),
    LazyRunner(check_type=CheckType.GITHUB_CONFIGURATION, module="checkov.github.runner"),
    LazyRunner(check_type=CheckType.GITHUB_ACTIONS),
    LazyRunner(check_type=CheckType.GITLAB_CONFIGURATION, module="checkov.gitlab.runner"),
    LazyRunner(check_type=CheckType.GITLAB_CI),
    LazyRunner(check_type=CheckType.HELM),
    LazyRunner(check_type=CheckType.JSON, module="checkov.json_doc.runner"),
    LazyRunner(check_type=CheckType.KUBERNETES),
    LazyRunner(check_type=CheckType.KUSTOMIZE),
    LazyRunner(check_type=CheckType.OPENAPI),
    LazyRunner(check_type=CheckType.SAST),
    LazyRunner(check_type=CheckType.SCA_PACKAGE, module="checkov.sca_package_2.runner"),
    LazyRunner(check_type=CheckType.SCA_IMAGE),
    LazyRunner(check_type=CheckType.SECRETS),
    LazyRunner(check_type=CheckType.SERVERLESS),
    LazyRunner(check_type=CheckType.TERRAFORM_PLAN, module="checkov.terraform.plan_runner"),
    LazyRunner(check_type=CheckType.TERRAFORM),
    LazyRunner(check_type=CheckType.TERRAFORM_JSON, cls="TerraformJsonRunner"),
    LazyRunner(check_type=CheckType.YAML, module="checkov.yaml_doc.runner"),
]
