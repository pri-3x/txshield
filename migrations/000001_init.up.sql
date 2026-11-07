-- TxShield initial schema.
--
-- Conventions:
--   * Addresses are stored as 20-byte BYTEA (compact, unambiguous casing).
--   * uint256 amounts are NUMERIC(78,0).
--   * Strings that originate on-chain (token symbols, contract names) are
--     UNTRUSTED display hints and are length-limited.
--   * Every analysis-derived row cascades from analyzed_transactions so that
--     retention purges remove everything derived from an analysis.

BEGIN;

CREATE TABLE analyzed_transactions (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id               TEXT CHECK (length(request_id) <= 64),
    chain_id                 BIGINT NOT NULL CHECK (chain_id > 0),
    -- Sender is stored only when TXSHIELD_STORE_SENDER=true (privacy).
    from_address             BYTEA CHECK (from_address IS NULL OR length(from_address) = 20),
    -- NULL for contract creation.
    to_address               BYTEA CHECK (to_address IS NULL OR length(to_address) = 20),
    value_wei                NUMERIC(78, 0) NOT NULL DEFAULT 0 CHECK (value_wei >= 0),
    selector                 BYTEA CHECK (selector IS NULL OR length(selector) = 4),
    calldata_hash            BYTEA NOT NULL CHECK (length(calldata_hash) = 32),
    -- Raw calldata only when TXSHIELD_STORE_CALLDATA=true.
    calldata                 BYTEA,
    block_number             BIGINT CHECK (block_number IS NULL OR block_number >= 0),
    decoded_method           TEXT CHECK (length(decoded_method) <= 256),
    call_kind                TEXT NOT NULL CHECK (call_kind IN ('native_transfer', 'contract_call', 'contract_creation', 'unknown')),
    risk_score               SMALLINT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_category            TEXT NOT NULL CHECK (risk_category IN ('low', 'moderate', 'elevated', 'high', 'critical')),
    confidence               TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    simulation_completeness  TEXT NOT NULL CHECK (simulation_completeness IN ('full', 'partial', 'none')),
    finding_count            INTEGER NOT NULL DEFAULT 0 CHECK (finding_count >= 0),
    report                   JSONB NOT NULL,
    engine_version           TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at               TIMESTAMPTZ
);

CREATE INDEX analyzed_transactions_created_at_idx ON analyzed_transactions (created_at DESC);
CREATE INDEX analyzed_transactions_chain_created_idx ON analyzed_transactions (chain_id, created_at DESC);
CREATE INDEX analyzed_transactions_to_idx ON analyzed_transactions (chain_id, to_address, created_at DESC) WHERE to_address IS NOT NULL;
CREATE INDEX analyzed_transactions_high_risk_idx ON analyzed_transactions (created_at DESC) WHERE risk_score >= 60;
CREATE INDEX analyzed_transactions_expires_idx ON analyzed_transactions (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE simulation_results (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id         UUID NOT NULL UNIQUE REFERENCES analyzed_transactions (id) ON DELETE CASCADE,
    backend             TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('success', 'reverted', 'not_run', 'error')),
    completeness        TEXT NOT NULL CHECK (completeness IN ('full', 'partial', 'none')),
    incomplete_reasons  TEXT[] NOT NULL DEFAULT '{}',
    chain_id            BIGINT NOT NULL,
    block_number        BIGINT NOT NULL,
    block_hash          BYTEA CHECK (block_hash IS NULL OR length(block_hash) = 32),
    gas_used            BIGINT NOT NULL DEFAULT 0 CHECK (gas_used >= 0),
    gas_estimate        BIGINT CHECK (gas_estimate IS NULL OR gas_estimate >= 0),
    -- Attacker-controlled text.
    revert_reason       TEXT CHECK (length(revert_reason) <= 1024),
    duration_ms         INTEGER NOT NULL DEFAULT 0,
    result              JSONB NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX simulation_results_status_idx ON simulation_results (status, created_at DESC);

CREATE TABLE security_findings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id  UUID NOT NULL REFERENCES analyzed_transactions (id) ON DELETE CASCADE,
    rule_id      TEXT NOT NULL CHECK (length(rule_id) <= 64),
    fingerprint  TEXT NOT NULL CHECK (length(fingerprint) <= 256),
    category     TEXT NOT NULL,
    severity     TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    confidence   TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    source       TEXT NOT NULL CHECK (source IN ('fact', 'heuristic', 'external')),
    title        TEXT NOT NULL CHECK (length(title) <= 256),
    finding      JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (analysis_id, fingerprint)
);

CREATE INDEX security_findings_rule_idx ON security_findings (rule_id, created_at DESC);
CREATE INDEX security_findings_severity_idx ON security_findings (severity, created_at DESC);

CREATE TABLE contract_metadata (
    chain_id                BIGINT NOT NULL,
    address                 BYTEA NOT NULL CHECK (length(address) = 20),
    is_contract             BOOLEAN NOT NULL,
    code_hash               BYTEA CHECK (code_hash IS NULL OR length(code_hash) = 32),
    code_size               INTEGER NOT NULL DEFAULT 0 CHECK (code_size >= 0),
    is_proxy                BOOLEAN NOT NULL DEFAULT false,
    implementation_address  BYTEA CHECK (implementation_address IS NULL OR length(implementation_address) = 20),
    -- NULL = unknown (no verification source configured).
    verified                BOOLEAN,
    verification_source     TEXT,
    standards               TEXT[] NOT NULL DEFAULT '{}',
    -- Untrusted display hint.
    name                    TEXT CHECK (length(name) <= 128),
    observed_block          BIGINT NOT NULL,
    first_seen_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, address)
);

CREATE INDEX contract_metadata_code_hash_idx ON contract_metadata (code_hash) WHERE code_hash IS NOT NULL;
CREATE INDEX contract_metadata_impl_idx ON contract_metadata (chain_id, implementation_address) WHERE implementation_address IS NOT NULL;

CREATE TABLE contract_reputation (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id     BIGINT NOT NULL,
    address      BYTEA NOT NULL CHECK (length(address) = 20),
    status       TEXT NOT NULL CHECK (status IN ('unknown', 'allowed', 'suspicious', 'blocked')),
    source       TEXT NOT NULL CHECK (length(source) <= 128),
    source_kind  TEXT NOT NULL CHECK (source_kind IN ('local', 'list', 'external')),
    reason       TEXT CHECK (length(reason) <= 1024),
    labels       TEXT[] NOT NULL DEFAULT '{}',
    confidence   TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    UNIQUE (chain_id, address, source)
);

CREATE INDEX contract_reputation_lookup_idx ON contract_reputation (chain_id, address);
CREATE INDEX contract_reputation_status_idx ON contract_reputation (status) WHERE status IN ('suspicious', 'blocked');

CREATE TABLE token_metadata (
    chain_id    BIGINT NOT NULL,
    address     BYTEA NOT NULL CHECK (length(address) = 20),
    standard    TEXT NOT NULL CHECK (standard IN ('erc20', 'erc721', 'erc1155', 'unknown')),
    -- Untrusted display hints: never used to identify a token.
    symbol      TEXT CHECK (length(symbol) <= 64),
    name        TEXT CHECK (length(name) <= 128),
    decimals    SMALLINT CHECK (decimals IS NULL OR decimals BETWEEN 0 AND 255),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, address)
);

-- Address -> analysis ledger powering the Address Inspector's
-- "interaction history available to TxShield".
CREATE TABLE analysis_history (
    analysis_id  UUID NOT NULL REFERENCES analyzed_transactions (id) ON DELETE CASCADE,
    chain_id     BIGINT NOT NULL,
    address      BYTEA NOT NULL CHECK (length(address) = 20),
    role         TEXT NOT NULL CHECK (role IN ('sender', 'target', 'spender', 'recipient', 'interacted', 'token')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (analysis_id, address, role)
);

CREATE INDEX analysis_history_address_idx ON analysis_history (chain_id, address, created_at DESC);

COMMIT;
