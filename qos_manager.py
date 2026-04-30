class QoSManager:
    def __init__(self, qos_profiles):
        self.qos_profiles = qos_profiles

    def get_queue_id(self, role):
        profile = self.qos_profiles.get(role)
        if profile is None:
            return self.qos_profiles["least"]["queue_id"]
        return profile["queue_id"]

    def get_profile(self, role):
        profile = self.qos_profiles.get(role)
        if profile is None:
            return self.qos_profiles["least"]
        return profile
