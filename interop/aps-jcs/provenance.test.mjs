import assert from 'node:assert/strict';
import test from 'node:test';
import { executionProvenance } from './provenance.mjs';

for (const repository of [
  'agent-passport-system/agent-passport-system',
  'astrogilda/agent-passport-system',
  'probityai/agent-evidence-vectors',
  'another-owner/receipt-ci',
]) {
  test(`hosted execution follows ${repository}`, () => {
    const report = executionProvenance({ GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: repository });
    assert.equal(report.controller, repository);
    assert.equal(report.operator, repository);
    assert.equal(report.workflow_repository, repository);
    assert.equal(report.execution, 'repository-operated');
    assert.equal(report.executor, 'GitHub Actions hosted runner');
    assert.deepEqual(report.harness_authorship,
      { author: 'astrogilda', repository: 'probityai/agent-evidence-vectors' });
  });
}

test('local execution does not infer its operator from the harness author', () => {
  for (const env of [{}, { GITHUB_ACTIONS: 'false', GITHUB_REPOSITORY: 'old-owner/old-repo' }]) {
    const report = executionProvenance(env);
    assert.equal(report.controller, null);
    assert.equal(report.operator, null);
    assert.equal(report.execution, 'operator-unrecorded');
    assert.equal(report.executor, 'local process');
    assert.equal('workflow_repository' in report, false);
    assert.equal(report.harness_authorship.author, 'astrogilda');
  }
});

test('hosted execution requires a valid workflow repository', () => {
  for (const repository of [undefined, '', 'astrogilda', '/repo', 'owner/repo/extra']) {
    assert.throws(() => executionProvenance({
      GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: repository,
    }), /GITHUB_REPOSITORY is required/);
  }
});
