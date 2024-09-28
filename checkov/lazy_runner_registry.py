from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from importlib import import_module

from checkov.common.bridgecrew.check_type import CheckType

if TYPE_CHECKING:
    from checkov.common.runners.base_runner import BaseRunner


@dataclass(frozen=True)
class LazyRunner:
    check_type: CheckType
    module: str | None = None
    cls: str = "Runner"

    def __post_init__(self):
        if self.module == self._inferred_module_qualname:
            raise ValueError(f"Redundant module name provided for {self!r}.")

    @property
    def _inferred_module_qualname(self) -> str:
        return f"checkov.{self.check_type}.runner"

    @property
    def _module_qualname(self) -> str:
        return self.module or self._inferred_module_qualname

    def load_runner_class(self) -> type[BaseRunner]:
        module = import_module(self._module_qualname)
        return getattr(module, self.cls)

    def load_runner(self) -> BaseRunner:
        return self.load_runner_class()()


# sca package runner added during the run method
LAZY_DEFAULT_RUNNERS: "list[LazyRunner]" = [
    LazyRunner(CheckType.ANSIBLE),
    LazyRunner(CheckType.ARGO_WORKFLOWS),
    LazyRunner(CheckType.ARM),
    LazyRunner(CheckType.AZURE_PIPELINES),
    LazyRunner(CheckType.BICEP),
    LazyRunner(CheckType.BITBUCKET_CONFIGURATION, module="checkov.bitbucket.runner"),
    LazyRunner(CheckType.BITBUCKET_PIPELINES),
    LazyRunner(CheckType.CDK, cls="CdkRunner"),
    LazyRunner(CheckType.CIRCLECI_PIPELINES),
    LazyRunner(CheckType.CLOUDFORMATION),
    LazyRunner(CheckType.DOCKERFILE),
    LazyRunner(CheckType.GITHUB_CONFIGURATION, module="checkov.github.runner"),
    LazyRunner(CheckType.GITHUB_ACTIONS),
    LazyRunner(CheckType.GITLAB_CONFIGURATION, module="checkov.gitlab.runner"),
    LazyRunner(CheckType.GITLAB_CI),
    LazyRunner(CheckType.HELM),
    LazyRunner(CheckType.JSON, module="checkov.json_doc.runner"),
    LazyRunner(CheckType.KUBERNETES),
    LazyRunner(CheckType.KUSTOMIZE),
    LazyRunner(CheckType.OPENAPI),
    LazyRunner(CheckType.SAST),
    LazyRunner(CheckType.SCA_PACKAGE, module="checkov.sca_package_2.runner"),
    LazyRunner(CheckType.SCA_IMAGE),
    LazyRunner(CheckType.SECRETS),
    LazyRunner(CheckType.SERVERLESS),
    LazyRunner(CheckType.TERRAFORM_PLAN, module="checkov.terraform.plan_runner"),
    LazyRunner(CheckType.TERRAFORM),
    LazyRunner(CheckType.TERRAFORM_JSON, cls="TerraformJsonRunner"),
    LazyRunner(CheckType.YAML, module="checkov.yaml_doc.runner"),
]
