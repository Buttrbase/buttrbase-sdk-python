import re

with open('src/buttrbase/client.py', 'r') as f:
    content = f.read()

# Add basic auth header to send_otp_v1
content = content.replace(
    """    def send_otp_v1(self, email: str, app_uuid: str) -> None:
        \"\"\"Send an email OTP. Flow: send_otp_v1 -> verify_otp_v1 -> finalize_registration.

        POST /api/v1/auth/otp/send
        \"\"\"
        self._request(
            "POST",
            "/api/v1/auth/otp/send",
            json={"email": email, "app_uuid": app_uuid},
            auth=False,
        )""",
    """    def send_otp_v1(self, email: str, app_uuid: str) -> None:
        \"\"\"Send an email OTP. Flow: send_otp_v1 -> verify_otp_v1 -> finalize_registration.

        POST /api/v1/auth/otp/send
        \"\"\"
        import base64
        secret = self.client_secret or ""
        b64 = base64.b64encode(f"{self.client_id}:{secret}".encode()).decode("utf-8")
        self._request(
            "POST",
            "/api/v1/auth/otp/send",
            json={"email": email, "app_uuid": app_uuid},
            auth=False,
            headers={"Authorization": f"Basic {b64}"}
        )"""
)

# And send_otp_email
content = content.replace(
    """    def send_otp_email(self, email: str, app_uuid: str) -> None:
        \"\"\"Alias for send_otp_v1.\"\"\"
        self.send_otp_v1(email, app_uuid)""",
    """    def send_otp_email(self, email: str, app_uuid: str) -> None:
        \"\"\"Alias for send_otp_v1.\"\"\"
        self.send_otp_v1(email, app_uuid)"""
)

# Update the _request method to take headers (if it doesn't already)
content = content.replace(
    """    def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        auth: bool = True,
    ) -> Any:""",
    """    def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        auth: bool = True,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:"""
)

content = content.replace(
    """        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }""",
    """        headers = headers or {}
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json" """
)

with open('src/buttrbase/client.py', 'w') as f:
    f.write(content)
