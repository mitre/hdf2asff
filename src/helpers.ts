import { AwsSecurityFinding } from "@aws-sdk/client-securityhub";
import { Control, HDF, Result } from "./types/hdf";
import _ from "lodash";
import { ContextualizedControl, ContextualizedEvaluation } from "inspecjs";

type Counts = {
  Passed: number;
  PassedTests: number;
  Failed: number;
  FailedTests: number;
  PassingTestsFailedControl: number;
  NotApplicable: number;
  NotReviewed: number;
};

export function getRunTime(hdf: HDF): Date {
  let time = new Date();
  hdf.profiles.forEach((profile) => {
    if (
      profile.controls[0].results.length &&
      profile.controls[0].results[0].start_time
    ) {
      time = new Date(profile.controls[0].results[0].start_time);
    }
  });
  return time;
}

/** Trivial overlay filter that just takes the version of the control that has results from amongst all identical ids */
function filter_overlays(
  controls: ContextualizedControl[]
): ContextualizedControl[] {
  const idHash: { [key: string]: ContextualizedControl } = {};
  controls.forEach((c) => {
    const id = c.hdf.wraps.id;
    const old: ContextualizedControl | undefined = idHash[id];
    // If old, gotta check if our new status list is "better than" old
    if (old) {
      const newSignificant = c.hdf.status_list && c.hdf.status_list.length > 0;
      if (newSignificant) {
        // Overwrite
        idHash[id] = c;
      }
    } else {
      // First time seeing this id
      idHash[id] = c;
    }
  });

  // Return the set of keys
  return Array.from(Object.values(idHash));
}

export function statusCount(evaluation: ContextualizedEvaluation): Counts {
  let controls: ContextualizedControl[] = [];
  // Get all controls
  evaluation.contains.forEach((p) => controls.push(...p.contains));
  controls = filter_overlays(controls);
  const statusCounts: Counts = {
    Passed: 0,
    PassedTests: 0,
    PassingTestsFailedControl: 0,
    Failed: 0,
    FailedTests: 0,
    NotApplicable: 0,
    NotReviewed: 0,
  };
  controls.forEach((control) => {
    if (control.hdf.status === "Passed") {
      statusCounts.Passed += 1;
      statusCounts.PassedTests += (control.hdf.segments || []).length;
    } else if (control.hdf.status === "Failed") {
      statusCounts.PassingTestsFailedControl += (
        control.hdf.segments || []
      ).filter((s) => s.status === "passed").length;
      statusCounts.FailedTests += (control.hdf.segments || []).filter(
        (s) => s.status === "failed"
      ).length;
      statusCounts.Failed += 1;
    } else if (control.hdf.status === "Not Applicable") {
      statusCounts.NotApplicable += 1;
    } else if (control.hdf.status === "Not Reviewed") {
      statusCounts.NotReviewed += 1;
    }
  });
  return statusCounts;
}

export function createDescription(counts: Counts): string {
  return `Passed: ${counts.Passed} (${
    counts.PassedTests
  } individual checks passed) --- Failed: ${counts.Failed} (${
    counts.PassingTestsFailedControl
  } individual checks failed out of ${
    counts.PassingTestsFailedControl + counts.FailedTests
  } total checks) --- Not Applicable: ${
    counts.NotApplicable
  } (System exception or absent component) --- Not Reviewed: ${
    counts.NotReviewed
  } (Can only be tested manually at this time)`;
}

export function createAssumeRolePolicyDocument(layersOfControl: (Control & { profileInfo?: Record<string, unknown> })[], segment: Result): string {
  const segmentOverview = createNote(segment)
  const code = layersOfControl.map((layer) => createCode(layer)).join("\n\n")
  return `${code}\n\n${segmentOverview}`
}

// Slices an array into chunks, since AWS doens't allow uploading more than 100 findings at a time
export function sliceIntoChunks(
  arr: AwsSecurityFinding[],
  chunkSize: number
): AwsSecurityFinding[][] {
  const res = [];
  for (let i = 0; i < arr.length; i += chunkSize) {
    const chunk = arr.slice(i, i + chunkSize);
    res.push(chunk);
  }
  return res;
}

// Gets rid of extra spacing + newlines as these aren't shown in Security Hub
export function cleanText(text?: string): string | undefined {
  if (text) {
    return text.replace(/  +/g, " ").replace(/\r?\n|\r/g, " ");
  } else {
    return undefined;
  }
}

// Gets all layers of a control accross overlaid profiles given the ID
export function getAllLayers(
  hdf: HDF,
  knownControl: Control
): (Control & { profileInfo?: Record<string, unknown> })[] {
  if (hdf.profiles.length == 1) {
    return [{ ...knownControl, ..._.omit(hdf.profiles, 'controls')}];
  } else {
    const foundControls: (Control & { profileInfo?: Record<string, unknown> })[] = [];
    // For each control in each profile
    hdf.profiles.forEach((profile) => {
      profile.controls.forEach((control) => {
        if (control.id === knownControl.id) {
          foundControls.push({ ...control, profileInfo: _.omit(profile, 'controls') });
        }
      });
    });
    return foundControls;
  }
}

// Creates Note field containing control status
export function createNote(segment: Result) {
  if (segment.message) {
    return `Test Description: ${segment.code_desc} --- Test Result: ${segment.message}`;
  } else if (segment.skip_message) {
    return `Test Description: ${segment.code_desc} --- Skip Message: ${segment.skip_message}`;
  } else {
    return `Test Description: ${segment.code_desc}`;
  }
}

export function createCode(control: Control & { profileInfo?: Record<string, unknown> }) {
  return `=========================================================\n# Profile name: ${control.profileInfo?.name}\n=========================================================\n\n${control.code.replace(/\\\"/g, "\"")}`;
}
