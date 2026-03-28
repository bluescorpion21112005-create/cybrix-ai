-- Create pentestdb for the FastAPI backend if it doesn't exist
SELECT 'CREATE DATABASE pentestdb OWNER appuser'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'pentestdb')\gexec
