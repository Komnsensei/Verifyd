'use strict';

function createTrace(mode) {
  const started_at = new Date().toISOString();
  const stages = [];

  function mark(stage, status, detail) {
    stages.push({
      stage,
      status: status || 'passed',
      detail: detail || null,
      at: new Date().toISOString()
    });
  }

  function fail(stage, code, detail) {
    mark(stage, 'failed', detail || code);
    const e = new Error(detail || code);
    e.code = code;
    e.engine_trace = stages.slice();
    throw e;
  }

  function all() {
    return {
      mode,
      started_at,
      completed_at: new Date().toISOString(),
      stages: stages.slice()
    };
  }

  return { mark, fail, all };
}

module.exports = { createTrace };
