class RBACManager:
    def __init__(self, policy):
        self.policy = policy

    def get_role(self, subject_id):
        return self.policy.get(subject_id, "least")
