from typing import Dict, Any, List


from checkov.terraform.context_parsers.base_parser import BaseContextParser


class ModuleContextParser(BaseContextParser):
    def __init__(self) -> None:
        definition_type = "module"
        super().__init__(definition_type=definition_type)

    def get_entity_context_path(self, entity_block: Dict[str, Dict[str, Any]]) -> List[str]:
        entity_name = next(iter(entity_block.keys()))
        return [entity_name]

    def enrich_definition_block(self, definition_blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
        for entity_block in definition_blocks:
            entity_name, entity_config = next(iter(entity_block.items()))
            self.context[entity_name] = {
                "start_line": entity_config[self.hcl2.START_LINE],
                "end_line": entity_config[self.hcl2.END_LINE],
                "code_lines": self.file_lines[entity_config[self.hcl2.START_LINE] - 1: entity_config[self.hcl2.END_LINE]],
            }

        return self.context


parser = ModuleContextParser()
