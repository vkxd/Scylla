class BasePlugin:
    def __init__(self, client):
        self.client = client

    async def run_all(self, target):
        raise NotImplementedError

    async def run_sub(self, sub_id, target):
        raise NotImplementedError
