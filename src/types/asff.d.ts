export interface ASFFFinding {
    SchemaVersion:         string;;
    Id:                    string;
    ProductArn:            string;
    //ProductName:           string;
    //CompanyName:           string;
    Region:                string;
    GeneratorId:           string;
    AwsAccountId:          string;
    Types:                 string[];
    FirstObservedAt:       string;
    LastObservedAt:        string;
    CreatedAt:             string;
    UpdatedAt:             string;
    Severity:              ASFFSeverity;
    Title:                 string;
    Description:           string;
    Remediation:           Remediation;
    ProductFields:         ProductFields;
    Resources:             Resource[];
    Compliance:            Compliance;
    //WorkflowState:         string;
    //Workflow:              Compliance;
    //ecordState:           string;
    //FindingProviderFields: FindingProviderFields;
}

export interface Compliance {
    Status: string;
    StatusReasons: StatusReason[];
}

export interface StatusReason {
    ReasonCode: string;
    Description: string;
}

export interface FindingProviderFields {
    Severity: FindingProviderFieldsSeverity;
    Types:    string[];
}

export interface FindingProviderFieldsSeverity {
    //Label:    string;
    //Original: string;
}

export interface ProductFields {
    [key: string]: string;
}

export interface Remediation {
    Recommendation: Recommendation;
}

export interface Recommendation {
    Text: string;
    Url:  string;
}

export interface Resource {
    Type:      string;
    Id:        string;
    Partition: string;
    Region:    string;
}

export interface ASFFSeverity {
    Product:    number;
    //Label:      string;
    Normalized: number;
    //Original:   string;
}
