export interface ASFFFinding {
  SchemaVersion: string;
  Id: string;
  ProductArn: string;
  Region: string;
  GeneratorId: string;
  AwsAccountId: string;
  Types: string[];
  CreatedAt: string;
  UpdatedAt: string;
  Severity: ASFFSeverity;
  Title: string;
  Description: string;
  Remediation: Remediation;
  ProductFields: ProductFields;
  Note?: Note;
  Resources: Resource[];
  Compliance: Compliance;
  UserDefinedFields?: { [key: string]: string };
  FindingProviderFields?: FindingProviderFields;
}

export interface Note {
  Text: string;
  UpdatedAt: string;
  UpdatedBy: string;
}

export interface FindingProviderFields {
  Confidence?: number;
  Criticality?: number;
  RelatedFindings?: RelatedFinding[];
  Severity: Severity;
  Types: string[];
}

export interface RelatedFinding {
  ProductArn: string;
  Id: string;
}

export interface Severity {
  Label: string;
  Original: string;
}

export interface Compliance {
  Status: string;
  StatusReasons: StatusReason[];
}

export interface StatusReason {
  ReasonCode: string;
  Description: string;
}

export interface ProductFields {
  [key: string]: string;
}

export interface Remediation {
  Recommendation: Recommendation;
}

export interface Recommendation {
  Text: string;
  Url?: string;
}

export interface Resource {
  Type: string;
  Id: string;
  Partition: string;
  Region: string;
}

export interface ASFFSeverity {
  Product: number;
  Normalized: number;
}
