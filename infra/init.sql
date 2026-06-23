-- Self-Healing API Platform - Database Schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Services Registry ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS services (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    base_url VARCHAR(512),
    description TEXT,
    team_email VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- ─── API Failures ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_failures (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_a VARCHAR(255) NOT NULL,
    service_b VARCHAR(255) NOT NULL,
    endpoint VARCHAR(512) NOT NULL,
    http_method VARCHAR(10),
    error_code INTEGER,
    error_type VARCHAR(100),
    request_payload JSONB,
    response_payload JSONB,
    error_message TEXT,
    detected_at TIMESTAMP DEFAULT NOW(),
    status VARCHAR(50) DEFAULT 'OPEN',   -- OPEN, ANALYZING, RESOLVED, IGNORED
    kafka_offset BIGINT
);

CREATE INDEX idx_api_failures_status ON api_failures(status);
CREATE INDEX idx_api_failures_services ON api_failures(service_a, service_b);
CREATE INDEX idx_api_failures_detected_at ON api_failures(detected_at DESC);

-- ─── AI Analysis Results ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS analysis_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    failure_id UUID REFERENCES api_failures(id) ON DELETE CASCADE,
    root_cause TEXT NOT NULL,
    confidence DECIMAL(5,2),
    transformation_rules JSONB,
    suggested_permanent_fix TEXT,
    ai_model VARCHAR(100),
    analyzed_at TIMESTAMP DEFAULT NOW(),
    status VARCHAR(50) DEFAULT 'PENDING_APPROVAL'  -- PENDING_APPROVAL, APPROVED, REJECTED
);

CREATE INDEX idx_analysis_results_failure ON analysis_results(failure_id);
CREATE INDEX idx_analysis_results_status ON analysis_results(status);

-- ─── Transformation Rules ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS transformation_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id UUID REFERENCES analysis_results(id) ON DELETE SET NULL,
    service_a VARCHAR(255) NOT NULL,
    service_b VARCHAR(255) NOT NULL,
    endpoint VARCHAR(512) NOT NULL,
    rule_type VARCHAR(50),               -- FIELD_RENAME, TYPE_COERCE, ADD_DEFAULT, REMOVE_FIELD
    rule_definition JSONB NOT NULL,
    description TEXT,
    approved_by VARCHAR(255),
    approved_at TIMESTAMP,
    expires_at TIMESTAMP,                -- TTL enforcement
    is_active BOOLEAN DEFAULT FALSE,
    version INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_rules_service_pair ON transformation_rules(service_a, service_b, endpoint);
CREATE INDEX idx_rules_active ON transformation_rules(is_active);
CREATE INDEX idx_rules_expires ON transformation_rules(expires_at);

-- ─── Approval Workflow ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS approval_workflow (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id UUID REFERENCES analysis_results(id) ON DELETE CASCADE,
    failure_id UUID REFERENCES api_failures(id) ON DELETE CASCADE,
    action VARCHAR(50),                  -- APPROVED, REJECTED
    acted_by VARCHAR(255),
    acted_at TIMESTAMP,
    comment TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ─── Audit Log ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_type VARCHAR(100),
    entity_id UUID,
    action VARCHAR(100),
    actor VARCHAR(255),
    details JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);

-- ─── Metrics ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS platform_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_date DATE DEFAULT CURRENT_DATE,
    total_failures INTEGER DEFAULT 0,
    auto_detected INTEGER DEFAULT 0,
    ai_analyzed INTEGER DEFAULT 0,
    rules_approved INTEGER DEFAULT 0,
    rules_rejected INTEGER DEFAULT 0,
    mttr_minutes DECIMAL(10,2),
    incidents_prevented INTEGER DEFAULT 0
);

-- ─── Dynamic Routing Rules ────────────────────────────────────────────────
-- Stores URL overrides when a service's DNS/address changes
CREATE TABLE IF NOT EXISTS routing_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_name VARCHAR(255) NOT NULL,          -- the service whose URL changed
    original_url VARCHAR(512) NOT NULL,          -- what we thought the URL was
    new_url VARCHAR(512) NOT NULL,               -- where we should actually route
    discovery_method VARCHAR(100),               -- DNS_PROBE | HEALTH_CHECK | MANUAL | AI_SUGGESTED
    failure_id UUID REFERENCES api_failures(id) ON DELETE SET NULL,
    analysis_id UUID REFERENCES analysis_results(id) ON DELETE SET NULL,
    approved_by VARCHAR(255),
    approved_at TIMESTAMP,
    is_active BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP,                        -- TTL
    probe_count INTEGER DEFAULT 0,               -- how many times probed
    last_probed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_routing_service ON routing_rules(service_name, is_active);
CREATE INDEX idx_routing_active ON routing_rules(is_active);

-- ─── CORS Rules ───────────────────────────────────────────────────────────
-- Stores dynamic CORS origin allowances when caller URLs change
CREATE TABLE IF NOT EXISTS cors_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_service VARCHAR(255) NOT NULL,        -- service B receiving the request
    allowed_origin VARCHAR(512) NOT NULL,        -- new origin of service A to allow
    previous_origin VARCHAR(512),               -- what the origin used to be
    failure_id UUID REFERENCES api_failures(id) ON DELETE SET NULL,
    analysis_id UUID REFERENCES analysis_results(id) ON DELETE SET NULL,
    allowed_methods VARCHAR(255) DEFAULT 'GET,POST,PUT,DELETE,OPTIONS',
    allowed_headers VARCHAR(512) DEFAULT '*',
    approved_by VARCHAR(255),
    approved_at TIMESTAMP,
    is_active BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_cors_service ON cors_rules(target_service, is_active);
CREATE INDEX idx_cors_active ON cors_rules(is_active);

-- ─── DNS Probe Log ────────────────────────────────────────────────────────
-- Audit trail of every DNS/health probe the platform performed
CREATE TABLE IF NOT EXISTS dns_probe_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_name VARCHAR(255) NOT NULL,
    probed_url VARCHAR(512) NOT NULL,
    http_status INTEGER,
    reachable BOOLEAN,
    response_time_ms INTEGER,
    error_message TEXT,
    probed_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_probe_service ON dns_probe_log(service_name, probed_at DESC);

-- ─── Seed Data ────────────────────────────────────────────────────────────
INSERT INTO services (name, base_url, description, team_email) VALUES
('order-service',   'http://order-service:8090',   'Handles order creation and management',  'orders@company.com'),
('user-service',    'http://user-service:8091',     'User profiles and authentication',        'users@company.com'),
('payment-service', 'http://payment-service:8092',  'Payment processing and refunds',          'payments@company.com'),
('inventory-service','http://inventory-service:8093','Product inventory tracking',             'inventory@company.com'),
('notification-svc','http://notification-svc:8094', 'Email and push notifications',            'platform@company.com')
ON CONFLICT (name) DO NOTHING;

-- ─── Migration V2: Custom Service Integration ──────────────────────────────

-- Extend services table with k8s + auth + health check fields
ALTER TABLE services
    ADD COLUMN IF NOT EXISTS namespace        VARCHAR(255) DEFAULT 'default',
    ADD COLUMN IF NOT EXISTS k8s_service_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS health_endpoint  VARCHAR(255) DEFAULT '/actuator/health',
    ADD COLUMN IF NOT EXISTS auth_type        VARCHAR(50)  DEFAULT 'NONE',
    -- NONE | JWT_BEARER | API_KEY_HEADER | API_KEY_QUERY | BASIC
    ADD COLUMN IF NOT EXISTS auth_header_name VARCHAR(255),
    -- e.g. 'Authorization', 'X-Api-Key'
    ADD COLUMN IF NOT EXISTS auth_secret_ref  VARCHAR(255),
    -- k8s secret name or env var name — never the actual secret
    ADD COLUMN IF NOT EXISTS timeout_ms       INTEGER      DEFAULT 10000,
    ADD COLUMN IF NOT EXISTS retry_count      INTEGER      DEFAULT 2,
    ADD COLUMN IF NOT EXISTS is_active        BOOLEAN      DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS last_health_check TIMESTAMP,
    ADD COLUMN IF NOT EXISTS last_health_status VARCHAR(20) DEFAULT 'UNKNOWN';

CREATE INDEX IF NOT EXISTS idx_services_active ON services(is_active);
CREATE INDEX IF NOT EXISTS idx_services_namespace ON services(namespace);

-- ─── Service Contracts ────────────────────────────────────────────────────
-- Stores example JSON payloads per service/endpoint as schema contracts
-- Claude uses these to give far better analysis than guessing from error alone
CREATE TABLE IF NOT EXISTS service_contracts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_name    VARCHAR(255) NOT NULL,
    endpoint        VARCHAR(512) NOT NULL,
    http_method     VARCHAR(10)  NOT NULL DEFAULT 'POST',
    direction       VARCHAR(10)  NOT NULL DEFAULT 'REQUEST',  -- REQUEST | RESPONSE
    example_payload JSONB        NOT NULL,
    description     TEXT,
    version         VARCHAR(50)  DEFAULT '1.0',
    registered_by   VARCHAR(255),
    is_active       BOOLEAN      DEFAULT TRUE,
    created_at      TIMESTAMP    DEFAULT NOW(),
    updated_at      TIMESTAMP    DEFAULT NOW(),
    UNIQUE (service_name, endpoint, http_method, direction, version)
);

CREATE INDEX idx_contracts_service    ON service_contracts(service_name, endpoint, direction);
CREATE INDEX idx_contracts_active     ON service_contracts(is_active);

-- ─── Response Transformation Rules ───────────────────────────────────────
-- Mirror of transformation_rules but applied to the RESPONSE from Service B
-- before it is returned to Service A
CREATE TABLE IF NOT EXISTS response_transformation_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id  UUID REFERENCES analysis_results(id) ON DELETE SET NULL,
    service_a    VARCHAR(255) NOT NULL,   -- the caller (who will receive the response)
    service_b    VARCHAR(255) NOT NULL,   -- the responder
    endpoint     VARCHAR(512) NOT NULL,
    rule_type    VARCHAR(50),             -- RESPONSE_FIELD_RENAME | RESPONSE_TYPE_COERCE
                                          -- RESPONSE_ADD_DEFAULT  | RESPONSE_REMOVE_FIELD
                                          -- RESPONSE_WRAP | RESPONSE_UNWRAP
    rule_definition JSONB NOT NULL,
    description  TEXT,
    approved_by  VARCHAR(255),
    approved_at  TIMESTAMP,
    expires_at   TIMESTAMP,
    is_active    BOOLEAN DEFAULT FALSE,
    version      INTEGER DEFAULT 1,
    created_at   TIMESTAMP DEFAULT NOW(),
    updated_at   TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_resp_rules_pair    ON response_transformation_rules(service_a, service_b, endpoint);
CREATE INDEX idx_resp_rules_active  ON response_transformation_rules(is_active);
CREATE INDEX idx_resp_rules_expires ON response_transformation_rules(expires_at);

-- ─── Auth Secrets (references only — actual secrets stay in k8s/env) ──────
-- Stores which env var / k8s secret holds the credential for each service.
-- The gateway resolves the actual value at runtime from env, never stored here.
CREATE TABLE IF NOT EXISTS service_auth_config (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_name    VARCHAR(255) NOT NULL UNIQUE,
    auth_type       VARCHAR(50)  NOT NULL, -- JWT_BEARER | API_KEY_HEADER | API_KEY_QUERY | BASIC | NONE
    header_name     VARCHAR(255),          -- e.g. Authorization, X-Api-Key
    query_param_name VARCHAR(255),         -- e.g. api_key (for API_KEY_QUERY)
    secret_env_var  VARCHAR(255),          -- env var name the gateway reads at runtime
    token_prefix    VARCHAR(50),           -- e.g. 'Bearer ', 'Token '
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_auth_config_service ON service_auth_config(service_name);

-- ─── k8s Health Check Cache ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS k8s_health_cache (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    service_name VARCHAR(255) NOT NULL,
    namespace    VARCHAR(255) NOT NULL DEFAULT 'default',
    k8s_dns      VARCHAR(512),   -- resolved k8s DNS name
    is_reachable BOOLEAN,
    response_ms  INTEGER,
    checked_at   TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_k8s_health_service ON k8s_health_cache(service_name, checked_at DESC);
