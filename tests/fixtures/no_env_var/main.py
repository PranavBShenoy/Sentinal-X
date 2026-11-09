"""
MISSING ENVIRONMENT VARIABLE FIXTURE.
Fails during initialization if DATABASE_URL is not provided.
Used to verify runtime crash detection and error diagnosis reporting.
"""
import os

# Fails with KeyError if required variable is missing
DATABASE_URL = os.environ["DATABASE_URL"]

print("Connected to:", DATABASE_URL)
