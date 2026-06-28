import re
from typing import List, Dict, Any
from datetime import datetime
from controller.models.tenant import Device

class GroupManager:
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
    
    def evaluate_device_groups(self, device: Device, groups_config: List[Dict[str, Any]]) -> List[str]:
        """Evaluate which groups a device belongs to based on conditions"""
        device_groups = []
        
        for group in groups_config:
            if self._evaluate_conditions(device, group.get('conditions', [])):
                device_groups.append(group['name'])
        
        return device_groups
    
    def _evaluate_conditions(self, device: Device, conditions: List[Dict[str, Any]]) -> bool:
        """Evaluate if all conditions match for a device"""
        if not conditions:
            return False
        
        for condition in conditions:
            if not self._evaluate_single_condition(device, condition):
                return False
        
        return True
    
    def _evaluate_single_condition(self, device: Device, condition: Dict[str, Any]) -> bool:
        """Evaluate a single condition"""
        condition_type = condition.get('type')
        operator = condition.get('operator')
        value = condition.get('value')
        
        if condition_type == 'device_model':
            return self._evaluate_string_condition(device.device_model, operator, value)
        elif condition_type == 'serial_number':
            return self._evaluate_string_condition(device.serial_number, operator, value)
        elif condition_type == 'hostname':
            return self._evaluate_string_condition(device.hostname or '', operator, value)
        elif condition_type == 'os_version':
            return self._evaluate_version_condition(device.os_version, operator, value)
        elif condition_type == 'enrollment_date':
            return self._evaluate_date_condition(device.enrollment_date, operator, value)
        
        return False
    
    def _evaluate_string_condition(self, device_value: str, operator: str, condition_value: Any) -> bool:
        """Evaluate string-based conditions"""
        if operator == 'regex':
            return bool(re.match(condition_value, device_value))
        elif operator == 'in':
            return device_value in condition_value
        elif operator == 'equals':
            return device_value == condition_value
        elif operator == 'contains':
            return condition_value in device_value
        
        return False
    
    def _evaluate_version_condition(self, device_version: str, operator: str, condition_value: str) -> bool:
        """Evaluate version-based conditions"""
        from packaging import version
        
        try:
            dev_ver = version.parse(device_version)
            cond_ver = version.parse(condition_value)
            
            if operator == 'gte':
                return dev_ver >= cond_ver
            elif operator == 'gt':
                return dev_ver > cond_ver
            elif operator == 'lte':
                return dev_ver <= cond_ver
            elif operator == 'lt':
                return dev_ver < cond_ver
            elif operator == 'equals':
                return dev_ver == cond_ver
        except:
            return False
        
        return False
    
    def _evaluate_date_condition(self, device_date: datetime, operator: str, condition_value: str) -> bool:
        """Evaluate date-based conditions"""
        try:
            cond_date = datetime.fromisoformat(condition_value)
            
            if operator == 'after':
                return device_date > cond_date
            elif operator == 'before':
                return device_date < cond_date
            elif operator == 'equals':
                return device_date.date() == cond_date.date()
        except:
            return False

        return False