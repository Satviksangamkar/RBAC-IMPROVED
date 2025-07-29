"""Casbin Redis adapter for policy storage."""
import json
import logging

logger = logging.getLogger(__name__)


class SyncRedisAdapter:
    """Simplified Redis adapter for Casbin policy storage."""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.policy_key = "casbin:policies"
        self.grouping_key = "casbin:grouping_policies"
    
    def is_filtered(self):
        """Return if the adapter is filtered or not."""
        return False
    
    def load_policy(self, model):
        """Load policies from Redis."""
        try:
            self.clear_policy()
            
            # Load policies and grouping policies
            for key, sections in [(self.policy_key, ["p", "p2", "p3"]), 
                                  (self.grouping_key, ["g", "g2", "g3"])]:
                data = self.redis.get(key)
                if data:
                    policies = json.loads(data)
                    for policy in policies:
                        if len(policy) >= 2:  # Minimum: ptype + content
                            self._load_policy_line(policy, model)
                        
            logger.info("Casbin policies loaded from Redis")
        except Exception as e:
            logger.error(f"Failed to load policies from Redis: {e}")
    
    def save_policy(self, model):
        """Save policies to Redis."""
        try:
            # Save regular and grouping policies
            policy_data = self._extract_policies(model, ["p", "p2", "p3"])
            grouping_data = self._extract_policies(model, ["g", "g2", "g3"])
            
            self.redis.set(self.policy_key, json.dumps(policy_data))
            self.redis.set(self.grouping_key, json.dumps(grouping_data))
            
            logger.info("Casbin policies saved to Redis")
            return True
        except Exception as e:
            logger.error(f"Failed to save policies to Redis: {e}")
            return False
    
    def _extract_policies(self, model, sections):
        """Extract policies for given sections."""
        policies = []
        for sec in sections:
            if sec in model.model and hasattr(model.model[sec], 'policy'):
                assertion = model.model[sec]
                for pvals in assertion.policy:
                    policies.append([sec] + pvals)
        return policies
    
    def add_policy(self, sec, ptype, rule):
        """Add a policy rule."""
        return True
    
    def remove_policy(self, sec, ptype, rule):
        """Remove a policy rule."""
        return True
    
    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """Remove filtered policy."""
        return True
    
    def clear_policy(self):
        """Clear all policies from storage."""
        try:
            self.redis.delete(self.policy_key)
            self.redis.delete(self.grouping_key)
        except Exception as e:
            logger.warning(f"Error clearing policies: {e}")
    
    def _load_policy_line(self, line, model):
        """Load a single policy line into the model."""
        if not line or len(line) < 2:
            return
        
        sec = line[0]  # Section (p, g, etc.)
        rule = line[1:]  # Rule content
        
        if sec in model.model:
            assertion = model.model[sec]
            assertion.policy.append(rule) 