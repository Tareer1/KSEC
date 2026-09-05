-- 014_timebound_workflow_versioning.sql
-- Time-bound authorization (spec 06#54): engagements carry a validity window.
-- Workflow versioning (spec 07): custom workflows get a version counter and
-- workflow runs snapshot the exact definition + version that executed, so an
-- executed run is immutable even if the workflow is edited later.

ALTER TABLE engagements ADD COLUMN valid_from TEXT;
ALTER TABLE engagements ADD COLUMN valid_until TEXT;

ALTER TABLE custom_workflows ADD COLUMN version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE workflow_runs ADD COLUMN definition_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE workflow_runs ADD COLUMN definition_snapshot TEXT NOT NULL DEFAULT '{}';