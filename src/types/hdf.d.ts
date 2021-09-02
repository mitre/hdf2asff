export interface HDF {
    platform:   Platform;
    profiles:   Profile[];
    statistics: Statistics;
    version:    string;
}

export interface Platform {
    name:    string;
    release: string;
}

export interface Profile {
    name:            string;
    version:         string;
    sha256:          string;
    title:           string;
    maintainer:      string;
    summary:         string;
    license:         string;
    copyright:       string;
    copyright_email: string;
    supports:        any[];
    attributes:      any[];
    groups:          Group[];
    controls:        Control[];
    status:          string;
}

export interface Control {
    id:              string;
    title:           string;
    desc:            string;
    descriptions?:    Description[];
    impact:          number;
    fix:             string;
    refs:            any[];
    tags:            {[key: string]: unknown};
    code:            string;
    source_location: SourceLocation;
    results:         Result[];
}

export interface Description {
    label: Label;
    data:  string;
}

export enum Label {
    Check = "check",
    Default = "default",
    Fix = "fix",
}

export interface Result {
    status:        Status;
    code_desc:     string;
    run_time:      number;
    start_time:    string;
    message?:      string;
    exception?:    string;
    resource?:     string;
    skip_message?: string;
}

export enum Status {
    Failed = "failed",
    Passed = "passed",
    Skipped = "skipped"
}

export interface SourceLocation {
    line: number;
    ref:  string;
}

export interface Dangerous {
    reason: string;
}

export interface Group {
    id:       string;
    controls: string[];
}

export interface Statistics {
    duration: number;
}
