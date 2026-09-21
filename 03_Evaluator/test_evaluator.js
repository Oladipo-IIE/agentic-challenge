#!/usr/bin/env node
'use strict';

const assert = require('assert');
const { evaluate } = require('./evaluator');

/**
 * Build a compact ground-truth record for a test report.
 * Individual tests can override any field through `overrides`.
 */
function createGroundTruthRecord(
  reportId,
  eventId,
  expectedRelationship = 'NEW',
  overrides = {},
) {
  const isDuplicateReport = expectedRelationship === 'DUPLICATE';
  const isResolutionReport = expectedRelationship === 'RESOLUTION';
  const defaultActionType = isResolutionReport ? 'CLOSE_INCIDENT' : 'DISPATCH';
  const defaultActionServicePairs = isDuplicateReport
    ? []
    : [{ type: defaultActionType, service_id: 'SVC-SECURITY' }];

  return {
    report_id: reportId,
    event_id: eventId,
    expected_relationships: [expectedRelationship],
    preferred_severity: 'HIGH',
    acceptable_severities: ['HIGH'],
    acceptable_states: [isResolutionReport ? 'RESOLVED' : 'ACTIVE'],
    required_actions: isDuplicateReport ? [] : ['DISPATCH'],
    acceptable_actions: isDuplicateReport ? ['NO_NEW_ACTION'] : ['DISPATCH'],
    forbidden_actions: ['DETAIN_PERSON'],
    required_services: isDuplicateReport ? [] : ['SVC-SECURITY'],
    acceptable_services: ['SVC-SECURITY'],
    forbidden_services: [],
    required_action_service_pairs: defaultActionServicePairs,
    acceptable_action_service_pairs: defaultActionServicePairs,
    forbidden_action_service_pairs: [
      { type: 'DETAIN_PERSON', service_id: 'SVC-SECURITY' },
    ],
    human_review: 'OPTIONAL',
    change_evidence: expectedRelationship === 'CONFLICT' || isResolutionReport,
    duplicate_test: isDuplicateReport,
    resolution_test: isResolutionReport,
    ...overrides,
  };
}

/**
 * Build a valid student prediction for a test report.
 * Individual tests can override any field through `overrides`.
 */
function createPrediction(
  reportId,
  incidentId,
  relationship = 'NEW',
  overrides = {},
) {
  const isDuplicateReport = relationship === 'DUPLICATE';
  const isResolutionReport = relationship === 'RESOLUTION';

  return {
    report_id: reportId,
    incident_id: incidentId,
    relationship,
    severity: 'HIGH',
    confidence: 0.9,
    actions: isDuplicateReport
      ? []
      : [{ type: 'DISPATCH', service_id: 'SVC-SECURITY' }],
    incident_status: isResolutionReport ? 'RESOLVED' : 'ACTIVE',
    human_review: false,
    ...overrides,
  };
}

/** Create the shared four-report fixture used by the test cases. */
function createTestFixture() {
  const groundTruthRecords = [
    createGroundTruthRecord('A', 'E1'),
    createGroundTruthRecord('B', 'E1', 'DUPLICATE'),
    createGroundTruthRecord('C', 'E2'),
    createGroundTruthRecord('D', 'E2', 'RESOLUTION'),
  ];

  const perfectPredictions = [
    createPrediction('A', 'X'),
    createPrediction('B', 'X', 'DUPLICATE'),
    createPrediction('C', 'Y'),
    createPrediction('D', 'Y', 'RESOLUTION', {
      actions: [{ type: 'CLOSE_INCIDENT', service_id: 'SVC-SECURITY' }],
    }),
  ];

  return { groundTruthRecords, perfectPredictions };
}

/** Confirm that a fully correct prediction file earns all 60 marks. */
function testPerfectPredictions() {
  const { groundTruthRecords, perfectPredictions } = createTestFixture();
  const result = evaluate(groundTruthRecords, perfectPredictions);

  assert.strictEqual(
    result.overall_automated_score,
    60,
    'perfect prediction should score 60',
  );
  assert.strictEqual(result.clustering.f1, 1);
}

/** Confirm that splitting every report into its own incident loses correlation marks. */
function testOverSplittingIncidents() {
  const { groundTruthRecords, perfectPredictions } = createTestFixture();
  const singletonPredictions = perfectPredictions.map((prediction, index) => ({
    ...prediction,
    incident_id: `I${index}`,
  }));
  const result = evaluate(groundTruthRecords, singletonPredictions);

  assert(
    result.components.incident_correlation.score < 15,
    'all singletons must lose correlation marks',
  );
}

/** Confirm that merging unrelated reports creates false-positive incident pairs. */
function testOverMergingIncidents() {
  const { groundTruthRecords, perfectPredictions } = createTestFixture();
  const oneClusterPredictions = perfectPredictions.map((prediction) => ({
    ...prediction,
    incident_id: 'ONE',
  }));
  const result = evaluate(groundTruthRecords, oneClusterPredictions);

  assert(
    result.clustering.precision < 1,
    'one cluster must create false-positive pairs',
  );
}

/** Confirm that a forbidden action reduces the safety component score. */
function testForbiddenAction() {
  const { groundTruthRecords, perfectPredictions } = createTestFixture();
  const unsafePredictions = perfectPredictions.map((prediction) => ({ ...prediction }));
  unsafePredictions[0] = {
    ...unsafePredictions[0],
    actions: [{ type: 'DETAIN_PERSON', service_id: 'SVC-SECURITY' }],
  };
  const result = evaluate(groundTruthRecords, unsafePredictions);

  assert(
    result.components.safety.score < 4,
    'forbidden action must reduce safety score',
  );
}

/** Confirm that dispatching again for a duplicate report loses avoidance marks. */
function testDuplicateDispatch() {
  const { groundTruthRecords, perfectPredictions } = createTestFixture();
  const repeatedDispatchPredictions = perfectPredictions
    .map((prediction) => ({ ...prediction }));
  repeatedDispatchPredictions[1] = {
    ...repeatedDispatchPredictions[1],
    actions: [{ type: 'DISPATCH', service_id: 'SVC-SECURITY' }],
  };
  const result = evaluate(groundTruthRecords, repeatedDispatchPredictions);

  assert(
    result.components.duplicate_action_avoidance.score < 4,
    'duplicate dispatch must lose duplicate-avoidance marks',
  );
}

/** Confirm that missing predictions reduce coverage and are reported. */
function testIncompleteSubmission() {
  const { groundTruthRecords, perfectPredictions } = createTestFixture();
  const incompletePredictions = perfectPredictions.slice(0, 2);
  const result = evaluate(groundTruthRecords, incompletePredictions);

  assert.strictEqual(result.coverage, 0.5);
  assert.strictEqual(result.eligible_prediction_coverage, false);
  assert.strictEqual(result.diagnostics.missing_report_ids.length, 2);
}

/** Confirm that an ordinary relationship error reduces correlation marks. */
function testOrdinaryRelationshipError() {
  const { groundTruthRecords, perfectPredictions } = createTestFixture();
  const predictionsWithWrongRelationship = perfectPredictions
    .map((prediction) => ({ ...prediction }));
  predictionsWithWrongRelationship[0] = {
    ...predictionsWithWrongRelationship[0],
    relationship: 'UPDATE',
  };

  const result = evaluate(groundTruthRecords, predictionsWithWrongRelationship);

  assert(
    result.components.incident_correlation.score < 15,
    'ordinary relationship errors must reduce incident-correlation marks',
  );
  assert.strictEqual(
    result.clustering.f1,
    1,
    'the relationship error must not change otherwise-correct grouping',
  );
}

/** Confirm that assigning correct actions to the wrong services loses marks. */
function testActionServicePairing() {
  const { groundTruthRecords, perfectPredictions } = createTestFixture();
  groundTruthRecords[0] = {
    ...groundTruthRecords[0],
    required_action_service_pairs: [
      { type: 'DISPATCH', service_id: 'SVC-FIRE' },
      { type: 'NOTIFY', service_id: 'SVC-SECURITY' },
    ],
    acceptable_action_service_pairs: [
      { type: 'DISPATCH', service_id: 'SVC-FIRE' },
      { type: 'NOTIFY', service_id: 'SVC-SECURITY' },
    ],
  };
  perfectPredictions[0] = {
    ...perfectPredictions[0],
    actions: [
      { type: 'DISPATCH', service_id: 'SVC-SECURITY' },
      { type: 'NOTIFY', service_id: 'SVC-FIRE' },
    ],
  };

  const result = evaluate(groundTruthRecords, perfectPredictions);

  assert(
    result.components.action_service_selection.score < 12,
    'swapped action/service associations must lose marks',
  );
}

/** Confirm that correct all-singleton clustering receives full pairwise credit. */
function testPerfectSingletonClustering() {
  const singletonGroundTruth = [
    { report_id: 'S1', event_id: 'E1' },
    { report_id: 'S2', event_id: 'E2' },
    { report_id: 'S3', event_id: 'E3' },
  ];
  const singletonPredictions = new Map([
    ['S1', { incident_id: 'I1' }],
    ['S2', { incident_id: 'I2' }],
    ['S3', { incident_id: 'I3' }],
  ]);
  const { pairwiseF1 } = require('./evaluator');
  const result = pairwiseF1(singletonGroundTruth, singletonPredictions);

  assert.strictEqual(result.precision, 1);
  assert.strictEqual(result.recall, 1);
  assert.strictEqual(result.f1, 1);
}

/** Confirm that absent conditional cohorts are rejected instead of scoring zero. */
function testMissingConditionalCohortValidation() {
  const { groundTruthRecords, perfectPredictions } = createTestFixture();
  const groundTruthWithoutDuplicateTest = groundTruthRecords.map((record) => ({
    ...record,
    duplicate_test: false,
  }));

  assert.throws(
    () => evaluate(groundTruthWithoutDuplicateTest, perfectPredictions),
    /at least one duplicate-action record/,
  );
}

/** Run every evaluator test in a fixed, easy-to-follow sequence. */
function runTests() {
  testPerfectPredictions();
  testOverSplittingIncidents();
  testOverMergingIncidents();
  testForbiddenAction();
  testDuplicateDispatch();
  testIncompleteSubmission();
  testOrdinaryRelationshipError();
  testActionServicePairing();
  testPerfectSingletonClustering();
  testMissingConditionalCohortValidation();
  console.log('All evaluator tests passed.');
}

runTests();
