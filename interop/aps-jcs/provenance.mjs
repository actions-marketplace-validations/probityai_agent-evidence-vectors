// Attribute execution to the workflow repository; authorship stays separate.
import assert from 'node:assert/strict';

export function executionProvenance(env = process.env) {
  const hosted = env.GITHUB_ACTIONS === 'true';
  const repository = hosted ? env.GITHUB_REPOSITORY : null;
  if (hosted) {
    assert.match(repository ?? '', /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
      'GITHUB_REPOSITORY is required for hosted execution');
  }
  return {
    harness_authorship: { author: 'astrogilda', repository: 'probityai/agent-evidence-vectors' },
    controller: repository,
    operator: repository,
    execution: hosted ? 'repository-operated' : 'operator-unrecorded',
    executor: hosted ? 'GitHub Actions hosted runner' : 'local process',
    ...(hosted ? { workflow_repository: repository } : {}),
  };
}
