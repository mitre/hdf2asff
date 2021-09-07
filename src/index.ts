import { Command } from 'commander';
import * as fs from 'fs';
import { ASFFFinding } from './types/asff';
import { HDF } from './types/hdf';
import * as _ from 'lodash';
import {createHash} from 'crypto'

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
const impactMapping: Map<number, string> = new Map([
    [0.9, 'CRITICAL'],
    [0.7, 'HIGH'],
    [0.5, 'MEDIUM'],
    [0.3, 'LOW'],
    [0.0, 'INFORMATIONAL']
  ]);

function sliceIntoChunks(arr: ASFFFinding[], chunkSize: number) {
    const res = [];
    for (let i = 0; i < arr.length; i += chunkSize) {
        const chunk = arr.slice(i, i + chunkSize);
        res.push(chunk);
    }
    return res;
}

// Gets rid of extra spacing + newlines as these aren't shown in Security Hub
function cleanText(text?: string): string | undefined {
    if (text){
        return text.replace(/  +/g, ' ').replace(/\r?\n|\r/g, '')
    } else {
        return undefined
    }
    
}

hdf.profiles.forEach((profile) => {
    profile.controls.forEach((control) => {
        control.results.forEach((segment) => {
            const controlStatus = segment.status == 'passed'
            const asffControl: ASFFFinding = {
                SchemaVersion: "2018-10-08",
                Id: `${profile.name}/${control.id}/finding/${options.input}/${createHash('sha256').update(segment.code_desc).digest('hex')}`,
                ProductArn: `arn:aws:securityhub:us-east-2:${options.awsAccountId}:product/${options.awsAccountId}/default`,
                AwsAccountId: options.awsAccountId,
                Types: ["Software and Configuration Checks"],
                CreatedAt: (control.results[0] || {start_time: new Date().toISOString()}).start_time,
                Region: options.region,
                UpdatedAt: new Date().toISOString(),
                GeneratorId: `arn:aws:securityhub:us-east-2:${options.awsAccountId}:ruleset/set/${profile.name}/v1.0.0/rule/${control.id}`,
                Title: _.truncate(`${profile.name}/${control.id} ${cleanText(control.title)}`, {length: 256}),
                Description: _.truncate(cleanText(control.desc), {length: 1024}),
                FindingProviderFields: {
                    Severity: {
                        Label: impactMapping.get(control.impact) || 'INFORMATIONAL',
                        Original: impactMapping.get(control.impact) || 'INFORMATIONAL'
                    },
                    Types: [`Profile/Name/${profile.name}`, `Profile/Version/${profile.version}`, `Profile/SHA256/${profile.sha256}`, `Profile/Title/${profile.title}`, `Profile/Maintainer/${profile.maintainer}`, `Profile/Summary/${profile.summary}`, `Profile/License/${profile.license}`, `Profile/Copyright/${profile.copyright}`,  `Profile/Copyright Email/${profile.copyright_email}`]
                },
                Remediation: {
                    Recommendation: {
                        Text: _.truncate(cleanText((control.descriptions?.find((description) => description.label === 'fix') || {data: control.fix || 'Fix not available'}).data), {length: 512})
                    }
                },
                ProductFields: {
                    "Provider Name": "AWS Systems Manager Compliance"
                },
                Note: {
                    Text: _.truncate(cleanText("Test Description: " + segment.code_desc + " --- Test Result: " + segment.message), {length: 512}),
                    UpdatedAt: new Date().toISOString(),
                    UpdatedBy: 'Code Description',
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
                    RelatedRequirements: ['See notes for test results'],
                    Status: controlStatus ? 'PASSED' : 'FAILED',
                    StatusReasons: [
                        {
                            ReasonCode: controlStatus ? 'CONFIG_EVALUATIONS_EMPTY' : 'CLOUDTRAIL_METRIC_FILTER_NOT_VALID',
                            Description:  _.truncate(cleanText(segment.message) || 'Unavailable', {length: 2048})
                        }
                    ]
                }
            }
            for (const tag in control.tags) {
                if(control.tags[tag]) {
                    if(tag === 'nist' && Array.isArray(control.tags.nist)) {
                        asffControl.FindingProviderFields?.Types.push(`Tags/nist/${control.tags.nist.join(', ')}`)
                    } else if (tag === 'cci' && Array.isArray(control.tags.cci)) {
                        asffControl.FindingProviderFields?.Types.push(`Tags/cci/${control.tags.cci.join(', ')}`)
                    } else if (typeof control.tags[tag] === 'string') {
                        asffControl.FindingProviderFields?.Types.push(`Tags/${tag.replace(/\W/g, '')}/${(control.tags[tag] as string).replace(/\W/g, '')}`)
                    } else if (typeof control.tags[tag] === 'object' && Array.isArray(control.tags[tag])) {
                        asffControl.FindingProviderFields?.Types.push(`Tags/${tag.replace(/\W/g, '')}/${(control.tags[tag] as Array<string>).join(', ').replace(/\W/g, '')}`)
                    }
                }
            }
            findings.push(asffControl)
        })
    })
})

try {
    if(findings.length <= 100){
        fs.writeFileSync(options.output, JSON.stringify(findings))
    } else {
        sliceIntoChunks(findings, 100).forEach((chunk, index) => {
            fs.writeFileSync(`${options.output}.p${index+1}`, JSON.stringify(chunk))
        })
    }
    
  } catch (err) {
    console.error(err)
  }
  