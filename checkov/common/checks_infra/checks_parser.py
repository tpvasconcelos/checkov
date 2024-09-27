from __future__ import annotations

import logging
from typing import Dict, Any, List, Optional, Type, TYPE_CHECKING
from importlib import import_module

from checkov.common.bridgecrew.severities import get_severity
from checkov.common.checks_infra.solvers.complex_solvers import AndSolver, OrSolver, NotSolver
from checkov.common.checks_infra.solvers.connections_solvers import (
    ConnectionExistsSolver,
    ConnectionNotExistsSolver,
    AndConnectionSolver,
    OrConnectionSolver,
)
from checkov.common.checks_infra.solvers.filter_solvers import WithinFilterSolver
from checkov.common.checks_infra.solvers.connections_solvers.connection_one_exists_solver import \
    ConnectionOneExistsSolver
from checkov.common.checks_infra.solvers.resource_solvers import ExistsResourcerSolver, NotExistsResourcerSolver
from checkov.common.checks_infra.solvers.resource_solvers.base_resource_solver import BaseResourceSolver
from checkov.common.graph.checks_infra.base_check import BaseGraphCheck
from checkov.common.graph.checks_infra.base_parser import BaseGraphCheckParser
from checkov.common.graph.checks_infra.enums import SolverType
from checkov.common.graph.checks_infra.solvers.base_solver import BaseSolver
from checkov.common.util.env_vars_config import env_vars_config
from checkov.common.util.type_forcers import force_list

if TYPE_CHECKING:
    from checkov.common.checks_infra.solvers.attribute_solvers.base_attribute_solver import BaseAttributeSolver
    from checkov.common.checks_infra.solvers.complex_solvers.base_complex_solver import BaseComplexSolver
    from checkov.common.checks_infra.solvers.connections_solvers.base_connection_solver import BaseConnectionSolver
    from checkov.common.checks_infra.solvers.connections_solvers.complex_connection_solver import ComplexConnectionSolver
    from checkov.common.checks_infra.solvers.filter_solvers.base_filter_solver import BaseFilterSolver


_operators_to_attributes_solver_classes: dict[str, Type[BaseAttributeSolver]] = {
    "equals": ("equals_attribute_solver", "EqualsAttributeSolver"),
    "not_equals": ("not_equals_attribute_solver", "NotEqualsAttributeSolver"),
    "regex_match": ("regex_match_attribute_solver", "RegexMatchAttributeSolver"),
    "not_regex_match": ("not_regex_match_attribute_solver", "NotRegexMatchAttributeSolver"),
    "exists": ("exists_attribute_solver", "ExistsAttributeSolver"),
    "any": ("any_attribute_solver", "AnyResourceSolver"),
    "contains": ("contains_attribute_solver", "ContainsAttributeSolver"),
    "not_exists": ("not_exists_attribute_solver", "NotExistsAttributeSolver"),
    "within": ("within_attribute_solver", "WithinAttributeSolver"),
    "not_within": ("not_within_attribute_solver", "NotWithinAttributeSolver"),
    "not_contains": ("not_contains_attribute_solver", "NotContainsAttributeSolver"),
    "starting_with": ("starting_with_attribute_solver", "StartingWithAttributeSolver"),
    "not_starting_with": ("not_starting_with_attribute_solver", "NotStartingWithAttributeSolver"),
    "ending_with": ("ending_with_attribute_solver", "EndingWithAttributeSolver"),
    "not_ending_with": ("not_ending_with_attribute_solver", "NotEndingWithAttributeSolver"),
    "greater_than": ("greater_than_attribute_solver", "GreaterThanAttributeSolver"),
    "greater_than_or_equal": ("greater_than_or_equal_attribute_solver", "GreaterThanOrEqualAttributeSolver"),
    "less_than": ("less_than_attribute_solver", "LessThanAttributeSolver"),
    "less_than_or_equal": ("less_than_or_equal_attribute_solver", "LessThanOrEqualAttributeSolver"),
    "subset": ("subset_attribute_solver", "SubsetAttributeSolver"),
    "not_subset": ("not_subset_attribute_solver", "NotSubsetAttributeSolver"),
    "is_empty": ("is_empty_attribute_solver", "IsEmptyAttributeSolver"),
    "is_not_empty": ("is_not_empty_attribute_solver", "IsNotEmptyAttributeSolver"),
    "length_equals": ("length_equals_attribute_solver", "LengthEqualsAttributeSolver"),
    "length_not_equals": ("length_not_equals_attribute_solver", "LengthNotEqualsAttributeSolver"),
    "length_greater_than": ("length_greater_than_attribute_solver", "LengthGreaterThanAttributeSolver"),
    "length_greater_than_or_equal": ("length_greater_than_or_equal_attribute_solver", "LengthGreaterThanOrEqualAttributeSolver"),
    "length_less_than": ("length_less_than_attribute_solver", "LengthLessThanAttributeSolver"),
    "length_less_than_or_equal": ("length_less_than_or_equal_attribute_solver", "LengthLessThanOrEqualAttributeSolver"),
    "is_true": ("is_true_attribute_solver", "IsTrueAttributeSolver"),
    "is_false": ("is_false_attribute_solver", "IsFalseAttributeSolver"),
    "intersects": ("intersects_attribute_solver", "IntersectsAttributeSolver"),
    "not_intersects": ("not_intersects_attribute_solver", "NotIntersectsAttributeSolver"),
    "equals_ignore_case": ("equals_ignore_case_attribute_solver", "EqualsIgnoreCaseAttributeSolver"),
    "not_equals_ignore_case": ("not_equals_ignore_case_attribute_solver", "NotEqualsIgnoreCaseAttributeSolver"),
    "range_includes": ("range_includes_attribute_solver", "RangeIncludesAttributeSolver"),
    "range_not_includes": ("range_not_includes_attribute_solver", "RangeNotIncludesAttributeSolver"),
    "number_of_words_equals": ("number_of_words_equals_attribute_solver", "NumberOfWordsEqualsAttributeSolver"),
    "number_of_words_not_equals": ("number_of_words_not_equals_attribute_solver", "NumberOfWordsNotEqualsAttributeSolver"),
    "number_of_words_greater_than": ("number_of_words_greater_than_attribute_solver", "NumberOfWordsGreaterThanAttributeSolver"),
    "number_of_words_greater_than_or_equal": ("number_of_words_greater_than_or_equal_attribute_solver", "NumberOfWordsGreaterThanOrEqualAttributeSolver"),
    "number_of_words_less_than_or_equal": ("number_of_words_less_than_or_equal_attribute_solver", "NumberOfWordsLessThanOrEqualAttributeSolver"),
    "number_of_words_less_than": ("number_of_words_less_than_attribute_solver", "NumberOfWordsLessThanAttributeSolver"),
}
_attribute_solvers_cache: dict[str, Type[BaseAttributeSolver]] = {}

def get_operators_to_attributes_solver_class(solver: str, default=None) -> Type[BaseAttributeSolver]:
    if solver in _attribute_solvers_cache:
        return _attribute_solvers_cache[solver]
    if solver not in _operators_to_attributes_solver_classes:
        _attribute_solvers_cache[solver] = default
        return default
    module_prefix = "checkov.common.checks_infra.solvers.attribute_solvers"
    module_suffix, class_name = _operators_to_attributes_solver_classes[solver]
    module_qual = f"{module_prefix}.{module_suffix}"
    module = import_module(module_qual)
    klass =  getattr(module, class_name)
    _attribute_solvers_cache[solver] = klass
    return klass

operators_to_complex_solver_classes: dict[str, Type[BaseComplexSolver]] = {
    "and": AndSolver,
    "or": OrSolver,
    "not": NotSolver,
}

operator_to_connection_solver_classes: dict[str, Type[BaseConnectionSolver]] = {
    "exists": ConnectionExistsSolver,
    "one_exists": ConnectionOneExistsSolver,
    "not_exists": ConnectionNotExistsSolver
}

operator_to_complex_connection_solver_classes: dict[str, Type[ComplexConnectionSolver]] = {
    "and": AndConnectionSolver,
    "or": OrConnectionSolver,
}

operator_to_filter_solver_classes: dict[str, Type[BaseFilterSolver]] = {
    "within": WithinFilterSolver,
}

condition_type_to_solver_type = {
    "": SolverType.ATTRIBUTE,
    "attribute": SolverType.ATTRIBUTE,
    "connection": SolverType.CONNECTION,
    "filter": SolverType.FILTER,
    "resource": SolverType.RESOURCE,
}

operator_to_resource_solver_classes: dict[str, Type[BaseResourceSolver]] = {
    "exists": ExistsResourcerSolver,
    "not_exists": NotExistsResourcerSolver,
}

JSONPATH_PREFIX = "jsonpath_"


class GraphCheckParser(BaseGraphCheckParser):
    def validate_check_config(self, file_path: str, raw_check: dict[str, dict[str, Any]]) -> bool:
        missing_fields = []

        # check existence of metadata block
        if "metadata" in raw_check:
            metadata = raw_check["metadata"]
            if "id" not in metadata:
                missing_fields.append("metadata.id")
            if "name" not in metadata:
                missing_fields.append("metadata.name")
            if "category" not in metadata:
                missing_fields.append("metadata.category")
        else:
            missing_fields.extend(("metadata.id", "metadata.name", "metadata.category"))

        # check existence of definition block
        if "definition" not in raw_check:
            missing_fields.append("definition")

        if missing_fields:
            logging.warning(f"Custom policy {file_path} is missing required fields {', '.join(missing_fields)}")
            return False

        # check if definition block is not obviously invalid
        definition = raw_check["definition"]
        if not isinstance(definition, (list, dict)):
            logging.warning(
                f"Custom policy {file_path} has an invalid 'definition' block type '{type(definition).__name__}', "
                "needs to be either a 'list' or 'dict'"
            )
            return False

        return True

    def parse_raw_check(self, raw_check: Dict[str, Dict[str, Any]], **kwargs: Any) -> BaseGraphCheck:
        providers = self._get_check_providers(raw_check)
        policy_definition = raw_check.get("definition", {})
        check = self._parse_raw_check(policy_definition, kwargs.get("resources_types"), providers)
        check.id = raw_check.get("metadata", {}).get("id", "")
        check.name = raw_check.get("metadata", {}).get("name", "")
        check.category = raw_check.get("metadata", {}).get("category", "")
        check.frameworks = raw_check.get("metadata", {}).get("frameworks", [])
        severity = get_severity(raw_check.get("metadata", {}).get("severity", ""))
        if severity:
            check.severity = severity
        check.guideline = raw_check.get("metadata", {}).get("guideline")
        check.check_path = kwargs.get("check_path", "")
        solver = self.get_check_solver(check)
        solver.providers = providers
        check.set_solver(solver)

        return check

    @staticmethod
    def _get_check_providers(raw_check: Dict[str, Any]) -> List[str]:
        providers = raw_check.get("scope", {}).get("provider", [""])
        if isinstance(providers, list):
            return providers
        elif isinstance(providers, str):
            return [providers]
        else:
            return [""]

    def _parse_raw_check(self, raw_check: Dict[str, Any], resources_types: Optional[List[str]], providers: Optional[List[str]]) -> BaseGraphCheck:
        check = BaseGraphCheck()
        complex_operator = get_complex_operator(raw_check)
        if complex_operator:
            check.type = SolverType.COMPLEX
            check.operator = complex_operator
            sub_solvers = raw_check.get(complex_operator, [])

            # this allows flexibility for specifying the child conditions, and makes "not" more intuitive by
            # not requiring an actual list
            if isinstance(sub_solvers, dict):
                sub_solvers = [sub_solvers]

            for sub_solver in sub_solvers:
                check.sub_checks.append(self._parse_raw_check(sub_solver, resources_types, providers))
            resources_types_of_sub_solvers = [
                force_list(q.resource_types) for q in check.sub_checks if q is not None and q.resource_types is not None
            ]
            check.resource_types = list(set(sum(resources_types_of_sub_solvers, [])))
            if any(q.type in [SolverType.CONNECTION, SolverType.COMPLEX_CONNECTION] for q in check.sub_checks):
                check.type = SolverType.COMPLEX_CONNECTION

        else:
            resource_type = raw_check.get("resource_types", [])
            if (
                    not resource_type
                    or (isinstance(resource_type, str) and resource_type.lower() == "all")
                    or (isinstance(resource_type, list) and resource_type[0].lower() == "all")
            ):
                if env_vars_config.CKV_SUPPORT_ALL_RESOURCE_TYPE:
                    check.resource_types = ['all']
                else:
                    check.resource_types = resources_types or []

            elif "provider" in resource_type and providers:
                for provider in providers:
                    check.resource_types.append(f"provider.{provider.lower()}")
            elif isinstance(resource_type, str):
                #  for the case the "resource_types" value is a string, which can result in a silent exception
                check.resource_types = [resource_type]
            else:
                check.resource_types = resource_type

            connected_resources_type = raw_check.get("connected_resource_types", [])
            if connected_resources_type == ["All"] or connected_resources_type == "all":
                check.connected_resources_types = resources_types or []
            else:
                check.connected_resources_types = connected_resources_type

            condition_type = raw_check.get("cond_type", "")
            check.type = condition_type_to_solver_type.get(condition_type)
            if condition_type == "":
                check.operator = "any"
            else:
                check.operator = raw_check.get("operator", "")
            check.attribute = raw_check.get("attribute")
            check.attribute_value = raw_check.get("value")

        return check

    @staticmethod
    def get_solver_type_method(check: BaseGraphCheck) -> Optional[BaseAttributeSolver]:
        check.is_jsonpath_check = check.operator.startswith(JSONPATH_PREFIX)
        if check.is_jsonpath_check:
            solver = check.operator.replace(JSONPATH_PREFIX, '')
        else:
            solver = check.operator

        attributes_solver_class = get_operators_to_attributes_solver_class(solver, None)
        if attributes_solver_class is None:
            return attributes_solver_class
        return attributes_solver_class(
            check.resource_types, check.attribute, check.attribute_value, check.is_jsonpath_check
        )

    def get_check_solver(self, check: BaseGraphCheck) -> BaseSolver:
        sub_solvers: List[BaseSolver] = []
        if check.sub_checks:
            sub_solvers = []
            for sub_solver in check.sub_checks:
                sub_solvers.append(self.get_check_solver(sub_solver))

        type_to_solver = {
            SolverType.COMPLEX_CONNECTION: operator_to_complex_connection_solver_classes.get(
                check.operator, lambda *args: None
            )(sub_solvers, check.operator),
            SolverType.COMPLEX: operators_to_complex_solver_classes.get(check.operator, lambda *args: None)(
                sub_solvers, check.resource_types
            ),
            SolverType.ATTRIBUTE: self.get_solver_type_method(check),
            SolverType.CONNECTION: operator_to_connection_solver_classes.get(check.operator, lambda *args: None)(
                check.resource_types, check.connected_resources_types
            ),
            SolverType.FILTER: operator_to_filter_solver_classes.get(check.operator, lambda *args: None)(
                check.resource_types, check.attribute, check.attribute_value
            ),
            SolverType.RESOURCE: operator_to_resource_solver_classes.get(check.operator, lambda *args: None)(
                check.resource_types
            ),
        }

        solver = type_to_solver.get(check.type)  # type:ignore[arg-type]  # if not str will return None
        if not solver:
            raise NotImplementedError(f"solver type {check.type} with operator {check.operator} is not supported")
        return solver


class NXGraphCheckParser(GraphCheckParser):
    # TODO: delete after downstream adjustments
    pass


def get_complex_operator(raw_check: Dict[str, Any]) -> Optional[str]:
    for operator in operators_to_complex_solver_classes.keys():
        if raw_check.get(operator):
            return operator
    return None
