-- Windowed detection rules (spec 08#18 DETECTION ENGINE extension).
-- A rule with window_minutes set is count-based: it fires when the number of
-- events matching its filter (event_type + field/operator/value) inside the
-- time window reaches window_count, e.g. "5 auth_failures from one IP in
-- 5 minutes" (brute-force detection). The filter match value stays in
-- `value`; `window_count` is the threshold.
ALTER TABLE detection_rules ADD COLUMN window_minutes INTEGER;
ALTER TABLE detection_rules ADD COLUMN window_count INTEGER;
