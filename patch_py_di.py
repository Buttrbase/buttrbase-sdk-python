import re

with open('src/buttrbase/client.py', 'r') as f:
    content = f.read()

content = content.replace(
    """    def __init__(
        self,
        access_token: str = "",
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10.0,
        max_retries: int = 3,
        retry_base_delay: float = 0.5,
        client_id: str = "",
        client_secret: str = "",
    ) -> None:""",
    """    def __init__(
        self,
        access_token: str = "",
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10.0,
        max_retries: int = 3,
        retry_base_delay: float = 0.5,
        client_id: str = "",
        client_secret: str = "",
        session: Optional[requests.Session] = None,
    ) -> None:"""
)

content = content.replace(
    """        self.client_id = client_id
        self.client_secret = client_secret
        self._session = requests.Session()""",
    """        self.client_id = client_id
        self.client_secret = client_secret
        self._session = session or requests.Session()"""
)

with open('src/buttrbase/client.py', 'w') as f:
    f.write(content)
