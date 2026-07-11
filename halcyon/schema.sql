CREATE TABLE IF NOT EXISTS audit_log (
  id         bigserial PRIMARY KEY,
  ts         timestamptz NOT NULL DEFAULT now(),
  session_id text NOT NULL,
  module     text NOT NULL,
  event_type text NOT NULL,
  actor      text NOT NULL,
  details    jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS ix_audit_session_module ON audit_log (session_id, module, id);

CREATE TABLE IF NOT EXISTS progress (
  session_id text NOT NULL,
  module     text NOT NULL,
  core       boolean NOT NULL DEFAULT false,
  stretch    boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (session_id, module)
);
