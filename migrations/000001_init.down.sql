BEGIN;

DROP TABLE IF EXISTS analysis_history;
DROP TABLE IF EXISTS token_metadata;
DROP TABLE IF EXISTS contract_reputation;
DROP TABLE IF EXISTS contract_metadata;
DROP TABLE IF EXISTS security_findings;
DROP TABLE IF EXISTS simulation_results;
DROP TABLE IF EXISTS analyzed_transactions;

COMMIT;
