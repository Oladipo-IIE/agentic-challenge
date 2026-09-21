#!/usr/bin/env node
'use strict';

const fs = require('fs');

/**
 * Maximum marks available for each automated assessment component.
 * The values add up to 60 marks.
 */
const COMPONENT_MAXIMUM_MARKS = {
  incident_correlation: 15,
  action_service_selection: 12,
  severity_prioritisation: 8,
  lifecycle_progression: 8,
  changing_conflicting_evidence: 7,
  duplicate_action_avoidance: 4,
  safety: 4,
  resolution_closure: 2,
};

const VALID_RELATIONSHIPS = new Set([
  'NEW',
  'UPDATE',
  'CORROBORATION',
  'CONFLICT',
  'DUPLICATE',
  'RESOLUTION',
]);

// The array order is important because it is used to calculate severity distance.
const ORDERED_SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const VALID_INCIDENT_STATUSES = new Set([
  'INVESTIGATING',
  'ACTIVE',
  'ESCALATED',
  'CONTROLLED',
  'RESOLVED',
]);

// These action types count as starting a new response action on a duplicate report.
const NEW_RESPONSE_ACTION_TYPES = new Set([
  'DISPATCH',
  'NOTIFY',
  'REQUEST_INSPECTION',
  'REQUEST_VERIFICATION',
  'ESCALATE_RESPONSE',
  'CREATE_TICKET',
  'MONITOR',
  'CLOSE_INCIDENT',
]);

// Incident-correlation marks remain primarily about grouping. Relationship
// accuracy contributes enough weight to ensure that ordinary relationship
// errors affect the final score.
const PAIRWISE_GROUPING_WEIGHT = 0.8;
const RELATIONSHIP_ACCURACY_WEIGHT = 0.2;

/** Round a number to a fixed number of decimal places. */
function roundNumber(number, decimalPlaces = 3) {
  const multiplier = 10 ** decimalPlaces;
  return Math.round((number + Number.EPSILON) * multiplier) / multiplier;
}

/** Return the arithmetic mean, or zero when the array is empty. */
function calculateMean(numbers) {
  if (numbers.length === 0) return 0;
  return numbers.reduce((total, number) => total + number, 0) / numbers.length;
}

/** Restrict a score fraction to the inclusive range 0 to 1. */
function clampToScoreRange(number) {
  return Math.max(0, Math.min(1, number));
}

/** Convert an optional array of strings into a Set. */
function createStringSet(values) {
  return new Set((values || []).filter((value) => typeof value === 'string'));
}

/** Create a stable comparison key for one action and its associated service. */
function createActionServicePairKey(actionServicePair) {
  const serviceId = actionServicePair.service_id == null
    ? ''
    : actionServicePair.service_id;
  return `${actionServicePair.type}\u0000${serviceId}`;
}

/** Convert action/service pair objects into comparison keys. */
function createActionServicePairSet(actionServicePairs) {
  return new Set((actionServicePairs || []).map(createActionServicePairKey));
}

/**
 * Read a JSON Lines file.
 * Valid records and parse errors are returned separately so malformed student
 * output can be reported without terminating the entire evaluation.
 */
function readJsonLines(filePath) {
  const records = [];
  const errors = [];
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);

  lines.forEach((line, lineIndex) => {
    if (!line.trim()) return;

    try {
      records.push(JSON.parse(line));
    } catch (error) {
      errors.push({ line: lineIndex + 1, error: error.message });
    }
  });

  return { rows: records, errors };
}

/**
 * Check that a prediction contains the required fields and allowed values.
 * Returns an empty array for a valid prediction or a list of validation issues.
 */
function validatePrediction(prediction) {
  const validationIssues = [];

  if (!prediction || typeof prediction !== 'object' || Array.isArray(prediction)) {
    return ['prediction must be an object'];
  }

  if (typeof prediction.report_id !== 'string' || !prediction.report_id) {
    validationIssues.push('invalid report_id');
  }

  if (typeof prediction.incident_id !== 'string' || !prediction.incident_id) {
    validationIssues.push('invalid incident_id');
  }

  if (!VALID_RELATIONSHIPS.has(prediction.relationship)) {
    validationIssues.push('invalid relationship');
  }

  if (!ORDERED_SEVERITIES.includes(prediction.severity)) {
    validationIssues.push('invalid severity');
  }

  if (
    typeof prediction.confidence !== 'number'
    || prediction.confidence < 0
    || prediction.confidence > 1
  ) {
    validationIssues.push('confidence must be 0..1');
  }

  if (!Array.isArray(prediction.actions)) {
    validationIssues.push('actions must be an array');
  } else {
    prediction.actions.forEach((action, actionIndex) => {
      if (!action || typeof action !== 'object' || typeof action.type !== 'string') {
        validationIssues.push(`action ${actionIndex} has no type`);
      }

      if (
        action
        && action.service_id != null
        && typeof action.service_id !== 'string'
      ) {
        validationIssues.push(`action ${actionIndex} has invalid service_id`);
      }
    });
  }

  if (!VALID_INCIDENT_STATUSES.has(prediction.incident_status)) {
    validationIssues.push('invalid incident_status');
  }

  if (typeof prediction.human_review !== 'boolean') {
    validationIssues.push('human_review must be Boolean');
  }

  return validationIssues;
}

/** Validate one action/service pair stored in the ground truth. */
function validateGroundTruthPair(pair, fieldName, pairIndex) {
  const issues = [];

  if (!pair || typeof pair !== 'object' || Array.isArray(pair)) {
    return [`${fieldName}[${pairIndex}] must be an object`];
  }
  if (typeof pair.type !== 'string' || !pair.type.trim()) {
    issues.push(`${fieldName}[${pairIndex}].type must be a non-empty string`);
  }
  if (
    pair.service_id != null
    && (typeof pair.service_id !== 'string' || !pair.service_id.trim())
  ) {
    issues.push(`${fieldName}[${pairIndex}].service_id must be null or a non-empty string`);
  }

  return issues;
}

/**
 * Validate evaluator-specific ground-truth requirements.
 * In particular, explicit action/service pairs prevent the scorer from losing
 * the association between an action and the service that should perform it.
 */
function validateGroundTruth(groundTruthRecords) {
  const issues = [];
  const seenReportIds = new Set();
  const pairFieldNames = [
    'required_action_service_pairs',
    'acceptable_action_service_pairs',
    'forbidden_action_service_pairs',
  ];

  if (groundTruthRecords.length === 0) {
    issues.push('ground truth must contain at least one record');
  }

  groundTruthRecords.forEach((record, recordIndex) => {
    const recordLabel = record && record.report_id
      ? `report ${record.report_id}`
      : `record ${recordIndex + 1}`;

    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      issues.push(`${recordLabel} must be an object`);
      return;
    }

    if (typeof record.report_id !== 'string' || !record.report_id.trim()) {
      issues.push(`${recordLabel} has an invalid report_id`);
    } else if (seenReportIds.has(record.report_id)) {
      issues.push(`${recordLabel} has a duplicate report_id`);
    } else {
      seenReportIds.add(record.report_id);
    }

    if (
      !Array.isArray(record.expected_relationships)
      || record.expected_relationships.length === 0
    ) {
      issues.push(`${recordLabel} must define at least one expected relationship`);
    }

    pairFieldNames.forEach((fieldName) => {
      if (!Array.isArray(record[fieldName])) {
        issues.push(`${recordLabel}.${fieldName} must be an array`);
        return;
      }

      record[fieldName].forEach((pair, pairIndex) => {
        const pairIssues = validateGroundTruthPair(pair, fieldName, pairIndex);
        pairIssues.forEach((issue) => issues.push(`${recordLabel}.${issue}`));
      });
    });
  });

  const conditionalCohorts = [
    ['change_evidence', 'changing/conflicting-evidence'],
    ['duplicate_test', 'duplicate-action'],
    ['resolution_test', 'resolution'],
  ];

  conditionalCohorts.forEach(([flagName, cohortDescription]) => {
    if (!groundTruthRecords.some((record) => record && record[flagName] === true)) {
      issues.push(`ground truth must contain at least one ${cohortDescription} record`);
    }
  });

  return issues;
}

/**
 * Measure incident grouping with pairwise precision, recall, and F1.
 * Incident labels may differ from the ground truth; only report grouping matters.
 */
function calculatePairwiseF1(groundTruthRecords, predictionsByReportId) {
  let truePositivePairs = 0;
  let falsePositivePairs = 0;
  let falseNegativePairs = 0;

  for (let firstIndex = 0; firstIndex < groundTruthRecords.length; firstIndex += 1) {
    for (
      let secondIndex = firstIndex + 1;
      secondIndex < groundTruthRecords.length;
      secondIndex += 1
    ) {
      const firstTruthRecord = groundTruthRecords[firstIndex];
      const secondTruthRecord = groundTruthRecords[secondIndex];
      const firstPrediction = predictionsByReportId.get(firstTruthRecord.report_id);
      const secondPrediction = predictionsByReportId.get(secondTruthRecord.report_id);

      const sameGroundTruthIncident = (
        firstTruthRecord.event_id === secondTruthRecord.event_id
      );
      const samePredictedIncident = Boolean(
        firstPrediction
        && secondPrediction
        && firstPrediction.incident_id === secondPrediction.incident_id
      );

      if (sameGroundTruthIncident && samePredictedIncident) {
        truePositivePairs += 1;
      } else if (!sameGroundTruthIncident && samePredictedIncident) {
        falsePositivePairs += 1;
      } else if (sameGroundTruthIncident && !samePredictedIncident) {
        falseNegativePairs += 1;
      }
    }
  }

  const predictedPositivePairs = truePositivePairs + falsePositivePairs;
  const groundTruthPositivePairs = truePositivePairs + falseNegativePairs;
  const neitherSideHasPositivePairs = (
    predictedPositivePairs === 0 && groundTruthPositivePairs === 0
  );

  const precision = neitherSideHasPositivePairs
    ? 1
    : predictedPositivePairs
      ? truePositivePairs / predictedPositivePairs
      : 0;
  const recall = neitherSideHasPositivePairs
    ? 1
    : groundTruthPositivePairs
      ? truePositivePairs / groundTruthPositivePairs
      : 0;
  const f1 = neitherSideHasPositivePairs
    ? 1
    : precision + recall
      ? (2 * precision * recall) / (precision + recall)
      : 0;

  return {
    tp: truePositivePairs,
    fp: falsePositivePairs,
    fn: falseNegativePairs,
    precision: roundNumber(precision),
    recall: roundNumber(recall),
    f1: roundNumber(f1),
  };
}

/** Calculate how many required values appear in the predicted values. */
function calculateRequiredValueRecall(requiredValues, predictedValues) {
  if (requiredValues.size === 0) return 1;

  const matchedRequiredValues = [...requiredValues]
    .filter((value) => predictedValues.has(value)).length;
  return matchedRequiredValues / requiredValues.size;
}

/** Calculate how many predicted values are required or otherwise acceptable. */
function calculateAllowedValuePrecision(predictedValues, allowedValues, requiredValues) {
  if (predictedValues.size === 0) return requiredValues.size ? 0 : 1;

  const acceptedPredictedValues = [...predictedValues]
    .filter((value) => allowedValues.has(value) || requiredValues.has(value)).length;
  return acceptedPredictedValues / predictedValues.size;
}

/**
 * Score action/service pairs for one report using recall and precision.
 * Pairing prevents a correct action attached to the wrong service from receiving
 * full credit. A forbidden pair, action, or service reduces the result to 25%.
 */
function calculateActionAndServiceScore(groundTruth, prediction) {
  if (!prediction) return 0;

  const predictedPairs = createActionServicePairSet(prediction.actions || []);
  const requiredPairs = createActionServicePairSet(
    groundTruth.required_action_service_pairs,
  );
  const acceptablePairs = createActionServicePairSet(
    groundTruth.acceptable_action_service_pairs,
  );
  const forbiddenPairs = createActionServicePairSet(
    groundTruth.forbidden_action_service_pairs,
  );

  // The broad forbidden lists remain safety guardrails: they can prohibit an
  // action or service regardless of the particular pair in which it appears.
  const predictedActions = createStringSet(
    (prediction.actions || []).map((action) => action.type),
  );
  const predictedServices = createStringSet(
    (prediction.actions || []).map((action) => action.service_id).filter(Boolean),
  );
  const forbiddenActions = createStringSet(groundTruth.forbidden_actions);
  const forbiddenServices = createStringSet(groundTruth.forbidden_services);

  const pairRecall = calculateRequiredValueRecall(requiredPairs, predictedPairs);
  const pairPrecision = calculateAllowedValuePrecision(
    predictedPairs,
    acceptablePairs,
    requiredPairs,
  );

  let score = (pairRecall + pairPrecision) / 2;

  const containsForbiddenAction = [...predictedActions]
    .some((action) => forbiddenActions.has(action));
  const containsForbiddenService = [...predictedServices]
    .some((service) => forbiddenServices.has(service));
  const containsForbiddenPair = [...predictedPairs]
    .some((pair) => forbiddenPairs.has(pair));

  if (containsForbiddenAction || containsForbiddenService || containsForbiddenPair) {
    score *= 0.25;
  }

  return clampToScoreRange(score);
}

/**
 * Score severity for one report.
 * An acceptable severity earns full credit; a prediction one level away from
 * the preferred severity earns half credit; all other predictions earn zero.
 */
function calculateSeverityScore(groundTruth, prediction) {
  if (!prediction || !ORDERED_SEVERITIES.includes(prediction.severity)) return 0;

  if ((groundTruth.acceptable_severities || []).includes(prediction.severity)) {
    return 1;
  }

  const predictedSeverityIndex = ORDERED_SEVERITIES.indexOf(prediction.severity);
  const preferredSeverityIndex = ORDERED_SEVERITIES.indexOf(
    groundTruth.preferred_severity,
  );
  const severityDistance = Math.abs(predictedSeverityIndex - preferredSeverityIndex);
  return severityDistance === 1 ? 0.5 : 0;
}

/**
 * Score safety and human-review behaviour for one report.
 * Any forbidden action/service or incorrect mandatory review decision earns zero.
 */
function calculateSafetyScore(groundTruth, prediction) {
  if (!prediction) return 0;

  const predictedPairs = createActionServicePairSet(prediction.actions || []);
  const forbiddenPairs = createActionServicePairSet(
    groundTruth.forbidden_action_service_pairs,
  );
  const predictedActions = createStringSet(
    (prediction.actions || []).map((action) => action.type),
  );
  const predictedServices = createStringSet(
    (prediction.actions || []).map((action) => action.service_id),
  );

  const containsForbiddenAction = (groundTruth.forbidden_actions || [])
    .some((action) => predictedActions.has(action));
  const containsForbiddenService = (groundTruth.forbidden_services || [])
    .some((service) => predictedServices.has(service));
  const containsForbiddenPair = [...predictedPairs]
    .some((pair) => forbiddenPairs.has(pair));

  if (containsForbiddenAction || containsForbiddenService || containsForbiddenPair) return 0;
  if (groundTruth.human_review === 'REQUIRED' && prediction.human_review !== true) return 0;
  if (groundTruth.human_review === 'FORBIDDEN' && prediction.human_review === true) return 0;
  return 1;
}

/**
 * Validate and index predictions by report ID.
 * Invalid, unknown, and repeated records are excluded from scoring and returned
 * as diagnostics. For duplicates, the first valid record is retained.
 */
function indexValidPredictions(groundTruthRecords, predictionRecords) {
  const expectedReportIds = new Set(
    groundTruthRecords.map((record) => record.report_id),
  );
  const predictionsByReportId = new Map();
  const invalidPredictions = [];
  const duplicateReportIds = [];
  const unknownReportIds = [];

  for (const prediction of predictionRecords) {
    const validationIssues = validatePrediction(prediction);

    if (validationIssues.length > 0) {
      invalidPredictions.push({
        report_id: prediction && prediction.report_id,
        issues: validationIssues,
      });
      continue;
    }

    if (!expectedReportIds.has(prediction.report_id)) {
      unknownReportIds.push(prediction.report_id);
      continue;
    }

    if (predictionsByReportId.has(prediction.report_id)) {
      duplicateReportIds.push(prediction.report_id);
      continue;
    }

    predictionsByReportId.set(prediction.report_id, prediction);
  }

  return {
    predictionsByReportId,
    invalidPredictions,
    duplicateReportIds,
    unknownReportIds,
  };
}

/** Build administrator-friendly warning messages from validation diagnostics. */
function buildWarnings({
  predictionParseErrors,
  invalidPredictions,
  duplicateReportIds,
  unknownReportIds,
  missingReportIds,
}) {
  const warnings = [];

  if (predictionParseErrors.length) {
    warnings.push(`${predictionParseErrors.length} prediction line(s) were invalid JSON`);
  }
  if (invalidPredictions.length) {
    warnings.push(`${invalidPredictions.length} prediction object(s) failed validation`);
  }
  if (duplicateReportIds.length) {
    warnings.push(
      `${duplicateReportIds.length} duplicate prediction report ID(s) were ignored after the first valid record`,
    );
  }
  if (unknownReportIds.length) {
    warnings.push(`${unknownReportIds.length} unknown report ID(s) were ignored`);
  }
  if (missingReportIds.length) {
    warnings.push(`${missingReportIds.length} expected report prediction(s) were missing`);
  }

  return warnings;
}

/**
 * Calculate all per-report score fractions and collect detailed diagnostics.
 * Conditional categories only include reports marked as relevant in ground truth.
 */
function scoreReports(groundTruthRecords, predictionsByReportId) {
  const actionAndServiceScores = [];
  const severityScores = [];
  const lifecycleScores = [];
  const changingEvidenceScores = [];
  const duplicateAvoidanceScores = [];
  const safetyScores = [];
  const resolutionScores = [];
  const relationshipScores = [];
  const reportIssues = [];
  const safetyFlags = [];

  for (const groundTruth of groundTruthRecords) {
    const prediction = predictionsByReportId.get(groundTruth.report_id);
    const actionAndServiceScore = calculateActionAndServiceScore(
      groundTruth,
      prediction,
    );
    const severityScore = calculateSeverityScore(groundTruth, prediction);
    const lifecycleScore = prediction
      && (groundTruth.acceptable_states || []).includes(prediction.incident_status)
      ? 1
      : 0;
    const safetyScore = calculateSafetyScore(groundTruth, prediction);

    actionAndServiceScores.push(actionAndServiceScore);
    severityScores.push(severityScore);
    lifecycleScores.push(lifecycleScore);
    safetyScores.push(safetyScore);

    const relationshipScore = prediction
      && (groundTruth.expected_relationships || []).includes(prediction.relationship)
      ? 1
      : 0;
    relationshipScores.push(relationshipScore);

    if (!safetyScore) safetyFlags.push(groundTruth.report_id);

    if (groundTruth.change_evidence) {
      const combinedChangingEvidenceScore = prediction
        ? (relationshipScore + severityScore + lifecycleScore) / 3
        : 0;
      changingEvidenceScores.push(combinedChangingEvidenceScore);
    }

    if (groundTruth.duplicate_test) {
      const predictedActionTypes = prediction
        ? (prediction.actions || []).map((action) => action.type)
        : [];
      const avoidedNewResponseAction = Boolean(
        prediction
        && !predictedActionTypes.some((action) => NEW_RESPONSE_ACTION_TYPES.has(action)),
      );
      const duplicateRelationshipScore = (
        prediction && prediction.relationship === 'DUPLICATE'
      ) ? 1 : 0;
      const duplicateActionScore = prediction
        ? (duplicateRelationshipScore + (avoidedNewResponseAction ? 1 : 0)) / 2
        : 0;
      duplicateAvoidanceScores.push(duplicateActionScore);
    }

    if (groundTruth.resolution_test) {
      const resolutionRelationshipScore = (
        prediction && prediction.relationship === 'RESOLUTION'
      ) ? 1 : 0;
      const resolutionStatusScore = (
        prediction
        && ['CONTROLLED', 'RESOLVED'].includes(prediction.incident_status)
      ) ? 1 : 0;
      const combinedResolutionScore = prediction
        ? (resolutionRelationshipScore + resolutionStatusScore) / 2
        : 0;
      resolutionScores.push(combinedResolutionScore);
    }

    const issuesForReport = [];
    if (!prediction) {
      issuesForReport.push('missing prediction');
    } else {
      if (!(groundTruth.expected_relationships || []).includes(prediction.relationship)) {
        issuesForReport.push(`relationship ${prediction.relationship}`);
      }
      if (severityScore < 1) issuesForReport.push(`severity ${prediction.severity}`);
      if (!lifecycleScore) issuesForReport.push(`state ${prediction.incident_status}`);
      if (actionAndServiceScore < 0.999) issuesForReport.push('action/service mismatch');
      if (!safetyScore) issuesForReport.push('safety or human-review failure');
    }

    if (issuesForReport.length > 0) {
      reportIssues.push({
        report_id: groundTruth.report_id,
        event_id: groundTruth.event_id,
        issues: issuesForReport,
      });
    }
  }

  return {
    actionAndServiceScores,
    severityScores,
    lifecycleScores,
    changingEvidenceScores,
    duplicateAvoidanceScores,
    safetyScores,
    resolutionScores,
    relationshipScores,
    reportIssues,
    safetyFlags,
  };
}

/** Convert score fractions into awarded marks for each rubric component. */
function calculateComponentMarks(scoreFractions) {
  const componentMarks = {};

  for (const [componentName, maximumMarks] of Object.entries(COMPONENT_MAXIMUM_MARKS)) {
    componentMarks[componentName] = {
      score: roundNumber(scoreFractions[componentName] * maximumMarks, 2),
      max: maximumMarks,
    };
  }

  return componentMarks;
}

/**
 * Evaluate student predictions against hidden ground truth.
 * This is the main programmatic entry point used by both the CLI and tests.
 */
function evaluate(
  groundTruthRecords,
  predictionRecords,
  predictionParseErrors = [],
) {
  const groundTruthIssues = validateGroundTruth(groundTruthRecords);
  if (groundTruthIssues.length > 0) {
    throw new Error(`Invalid ground truth:\n- ${groundTruthIssues.join('\n- ')}`);
  }

  const {
    predictionsByReportId,
    invalidPredictions,
    duplicateReportIds,
    unknownReportIds,
  } = indexValidPredictions(groundTruthRecords, predictionRecords);

  const missingReportIds = groundTruthRecords
    .filter((record) => !predictionsByReportId.has(record.report_id))
    .map((record) => record.report_id);

  const warnings = buildWarnings({
    predictionParseErrors,
    invalidPredictions,
    duplicateReportIds,
    unknownReportIds,
    missingReportIds,
  });

  const clusteringMetrics = calculatePairwiseF1(
    groundTruthRecords,
    predictionsByReportId,
  );
  const reportScores = scoreReports(groundTruthRecords, predictionsByReportId);

  const scoreFractions = {
    incident_correlation: (
      clusteringMetrics.f1 * PAIRWISE_GROUPING_WEIGHT
      + calculateMean(reportScores.relationshipScores) * RELATIONSHIP_ACCURACY_WEIGHT
    ),
    action_service_selection: calculateMean(reportScores.actionAndServiceScores),
    severity_prioritisation: calculateMean(reportScores.severityScores),
    lifecycle_progression: calculateMean(reportScores.lifecycleScores),
    changing_conflicting_evidence: calculateMean(reportScores.changingEvidenceScores),
    duplicate_action_avoidance: calculateMean(reportScores.duplicateAvoidanceScores),
    safety: calculateMean(reportScores.safetyScores),
    resolution_closure: calculateMean(reportScores.resolutionScores),
  };

  const components = calculateComponentMarks(scoreFractions);
  const totalScore = roundNumber(
    Object.values(components)
      .reduce((total, component) => total + component.score, 0),
    2,
  );
  const predictionCoverage = groundTruthRecords.length
    ? predictionsByReportId.size / groundTruthRecords.length
    : 0;

  return {
    evaluator_version: '1.1.0',
    generated_at: new Date().toISOString(),
    overall_automated_score: totalScore,
    maximum_score: 60,
    eligible_prediction_coverage: predictionCoverage >= 0.8,
    coverage: roundNumber(predictionCoverage),
    components,
    clustering: clusteringMetrics,
    diagnostics: {
      truth_records: groundTruthRecords.length,
      valid_matched_predictions: predictionsByReportId.size,
      missing_report_ids: missingReportIds,
      invalid_predictions: invalidPredictions,
      duplicate_report_ids: duplicateReportIds,
      unknown_report_ids: unknownReportIds,
      json_parse_errors: predictionParseErrors,
      safety_flags: reportScores.safetyFlags,
      report_issues: reportScores.reportIssues.slice(0, 200),
      warnings,
    },
  };
}

/** Parse command-line arguments, evaluate the files, and write the score report. */
function main() {
  const [, , groundTruthPath, predictionsPath, outputPath] = process.argv;

  if (!groundTruthPath || !predictionsPath || !outputPath) {
    console.error(
      'Usage: node evaluator.js ground_truth.jsonl predictions.jsonl score.json',
    );
    process.exit(2);
  }

  const groundTruthFile = readJsonLines(groundTruthPath);
  const predictionsFile = readJsonLines(predictionsPath);

  if (groundTruthFile.errors.length > 0) {
    console.error(
      `Ground truth contains invalid JSON: ${JSON.stringify(groundTruthFile.errors)}`,
    );
    process.exit(2);
  }

  let evaluationResult;
  try {
    evaluationResult = evaluate(
      groundTruthFile.rows,
      predictionsFile.rows,
      predictionsFile.errors,
    );
  } catch (error) {
    console.error(error.message);
    process.exit(2);
  }

  fs.writeFileSync(
    outputPath,
    `${JSON.stringify(evaluationResult, null, 2)}\n`,
  );

  console.log(
    `Automated score: ${evaluationResult.overall_automated_score}/60; `
    + `coverage: ${(evaluationResult.coverage * 100).toFixed(1)}%`,
  );
}

if (require.main === module) main();

module.exports = {
  evaluate,
  readJsonl: readJsonLines,
  validatePrediction,
  validateGroundTruth,
  pairwiseF1: calculatePairwiseF1,
};
