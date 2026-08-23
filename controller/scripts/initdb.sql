-- Create database schema
CREATE
EXTENSION IF NOT EXISTS "uuid-ossp";

-- check if database exists
-- CREATE DATABASE mdm_iac;

-- Create schema for mdm
CREATE SCHEMA IF NOT EXISTS mdm;

-- Grant permissions
GRANT
ALL
ON SCHEMA mdm TO postgres;
