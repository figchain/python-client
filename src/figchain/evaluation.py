import math
import uuid
from typing import Dict, Any, Optional
from .models import FigFamily, Rule, Condition, Operator, Fig

Context = Dict[str, str]

class Evaluator:
    def evaluate(self, family: FigFamily, context: Context) -> Optional[Fig]:
        version_id = None
        
        # 1. Rules
        if family.rules:
            for rule in family.rules:
                if self.matches(rule, context):
                    version_id = str(rule.targetVersion)
                    break
        
        # 2. Default
        if not version_id and family.defaultVersion:
             version_id = str(family.defaultVersion)
             
        # Find fig by version
        if version_id:
            for fig in family.figs:
                if str(fig.version) == version_id:
                    return fig
                    
        # 3. Fallback to first available (usually latest)
        if family.figs:
            return family.figs[0]
            
        return None

    def matches(self, rule: Rule, context: Context) -> bool:
        if not rule.conditions:
            return True
        for condition in rule.conditions:
            if not self.evaluate_condition(condition, context):
                return False
        return True

    def evaluate_condition(self, condition: Condition, context: Context) -> bool:
        var_name = condition.variable
        ctx_value = context.get(var_name)
        
        if ctx_value is None:
            return False
            
        op = condition.operator
        rule_values = condition.values or []
        rule_value = rule_values[0] if rule_values else None
        
        if op == Operator.EQUALS:
            return ctx_value == rule_value
        elif op == Operator.NOT_EQUALS:
            return ctx_value != rule_value
        elif op == Operator.IN:
            return ctx_value in rule_values
        elif op == Operator.NOT_IN:
            return ctx_value not in rule_values
        elif op == Operator.CONTAINS:
            return rule_value is not None and rule_value in ctx_value
        elif op == Operator.GREATER_THAN:
            return rule_value is not None and ctx_value > rule_value
        elif op == Operator.LESS_THAN:
            return rule_value is not None and ctx_value < rule_value
        elif op == Operator.SPLIT:
             if rule_value is None: return False
             try:
                 threshold = int(rule_value)
                 bucket = self.get_bucket(ctx_value)
                 return bucket < threshold
             except ValueError:
                 return False
        
        return False

    def get_bucket(self, key: str) -> int:
        hash_val = 2166136261 # 0x811c9dc5 unsigned
        prime = 16777619 # 0x01000193 unsigned
        
        for byte in key.encode('utf-8'):
            hash_val = (hash_val ^ byte) & 0xFFFFFFFF
            hash_val = (hash_val * prime) & 0xFFFFFFFF
            
        # Convert to signed 32-bit int
        if hash_val > 0x7FFFFFFF:
            hash_val -= 0x100000000
            
        return int(abs(math.fmod(hash_val, 100)))
