"""
INTENTIONALLY LEAKED SECRET FIXTURE.
FOR TESTING ONLY — ALL STRINGS ARE FAKE SIMULATED VALUES.
Used to verify Gitleaks secret detection and secret masking logic.
"""

# FAKE TEST TOKEN (Simulated AWS Access Key ID format)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# FAKE TEST SECRET (Simulated AWS Secret Access Key format)
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# FAKE TEST API KEY (Simulated generic high-entropy API key for secret detection)
GENERIC_API_KEY = "x7a9k2m4p8q1v3w5y8z0b2d4f6h8j0l2n4"

# FAKE DATABASE PASSWORD
DATABASE_URL = "postgresql://admin:P@ssw0rdFakeTest123@localhost:5432/production_db"
