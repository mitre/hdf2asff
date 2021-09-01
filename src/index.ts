import { Command } from 'commander';
import fs from 'fs'
import { ASFFFinding } from './types/asff';
import { HDF } from './types/hdf';
import _ from 'lodash';
const program = new Command();
program.version('1.0.0')

interface iOptions {
    input: string;
    output: string;
    awsAccountId: string;
    region: string;
}

program
  .requiredOption('-i, --input <infile>', 'Input HDF/InSpec JSON')
  .requiredOption('-o, --output <outfile>', 'Output ASFF Findings JSON')
  .requiredOption('-a, --aws-account-id <accountid>', 'AWS Account ID')
  .requiredOption('-r, --region <region>', 'AWS Account Region');

program.parse(process.argv);
program.showHelpAfterError()

const options: iOptions = program.opts();
const hdf: HDF = JSON.parse(fs.readFileSync(options.input, {encoding:'utf8', flag:'r'}))
const findings: ASFFFinding[] = []

function sliceIntoChunks(arr: ASFFFinding[], chunkSize: number) {
    const res = [];
    for (let i = 0; i < arr.length; i += chunkSize) {
        const chunk = arr.slice(i, i + chunkSize);
        res.push(chunk);
    }
    return res;
}

hdf.profiles.forEach((profile) => {
    profile.controls.forEach((control) => {
        const controlStatus = control.results.every((result) => (result.status === 'passed' || result.status === 'skipped'))
        findings.push({
            SchemaVersion: "2018-10-08",
            Id: `${profile.name}/${control.id}`,
            ProductArn: `arn:aws:securityhub:us-east-2:${options.awsAccountId}:product/${options.awsAccountId}/default`,
            AwsAccountId: options.awsAccountId,
            Types: ["Software and Configuration Checks"],
            FirstObservedAt: control.results[0].start_time || new Date().toISOString(),
            LastObservedAt: control.results[0].start_time || new Date().toISOString(),
            CreatedAt: control.results[0].start_time || new Date().toISOString(),
            Region: options.region,
            UpdatedAt: new Date().toISOString(),
            GeneratorId: `arn:aws:securityhub:us-east-2:${options.awsAccountId}:ruleset/set/${profile.name}/v1.0.0/rule/${control.id}`,
            Title: _.truncate(control.title, {length: 256}),
            Description: _.truncate(control.desc, {length: 1024}),
            Remediation: {
                Recommendation: {
                    Text: _.truncate((control.descriptions.find((description) => description.label === 'fix') || {data: control.fix || 'Fix not available'}).data, {length: 512}),
                    Url: control.tags.nist[0] ? `https://www.stigviewer.com/controls/800-53/${control.tags.nist[0].split(' ')[0]}` : ''
                }
            },
            ProductFields: {
                "Provider Name": "AWS Systems Manager Compliance"
            },
            Severity: {
                Product: 1,
                Normalized: 10,
            },
            Resources: [
                {
                    Type: "AwsAccount",
                    Id: `AWS::::Account:${options.awsAccountId}`,
                    Partition: "aws",
                    Region: options.region
                }
            ],
            Compliance: {
                Status: controlStatus ? 'PASSED' : 'FAILED',
                StatusReasons: [
                    {
                        ReasonCode: controlStatus ? 'CONFIG_EVALUATIONS_EMPTY' : 'CLOUDTRAIL_METRIC_FILTER_NOT_VALID',
                        Description: _.truncate(control.results.map((result) => result.code_desc + "\n\n" + result.message).join('\n\n'), {length: 2048})
                    }
                ]
            }
        })
    })
})

try {
    if(findings.length <= 100){
        fs.writeFileSync(options.output, JSON.stringify(findings))
    } else {
        sliceIntoChunks(findings, 100).forEach((chunk, index) => {
            fs.writeFileSync(`${options.output}.p${index}`, JSON.stringify(chunk))
        })
    }
    
  } catch (err) {
    console.error(err)
  }
  