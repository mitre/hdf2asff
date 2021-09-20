import { Command } from 'commander';
import * as fs from 'fs';
import { Control, HDF } from './types/hdf';
import _ from 'lodash';
import {createHash} from 'crypto'
import { SecurityHubClient, BatchImportFindingsCommand, AwsSecurityFinding } from "@aws-sdk/client-securityhub";
import {createLogger, transports, format} from 'winston'

const logger = createLogger({
    transports: [new transports.Console({
        level: 'info',
        format: format.combine(
          format.colorize(),
          format.simple()
        )
      })
  ]
})

// Proccess comamand input
interface iOptions {
    input: string;
    output: string;
    awsAccountId: string;
    accessKeyId?: string;
    accessKeySecret?: string;
    target: string;
    region: string;
    upload?: boolean;
}

const program = new Command();
program.version('1.0.0')
program
  .requiredOption('-i, --input <infile>', 'Input HDF/InSpec JSON')
  .requiredOption('-o, --output <outfile>', 'Output ASFF Findings JSON')
  .requiredOption('-a, --aws-account-id <accountid>', 'AWS Account ID')
  .requiredOption('-r, --region <region>', 'AWS Account Region')
  .requiredOption('-t, --target <target>', 'Name of targeted host (re-use target to preserve findings across time)')
  .option('-a, --access-key <accessKeyId>')
  .option('-a, --access-key-secret <accessKeySecret>')
  .option('-u, --upload', 'Automattically upload findings to Security Hub (AWS CLI must be configured or secrets must be passed)');

program.parse(process.argv);
program.showHelpAfterError()
const options: iOptions = program.opts();

const target = options.target.toLowerCase().trim()
const hdf: HDF = JSON.parse(fs.readFileSync(options.input, {encoding:'utf8', flag:'r'}))
const findings: AwsSecurityFinding[] = []
const impactMapping: Map<number, string> = new Map([
    [0.9, 'CRITICAL'],
    [0.7, 'HIGH'],
    [0.5, 'MEDIUM'],
    [0.3, 'LOW'],
    [0.0, 'INFORMATIONAL']
]);

function sliceIntoChunks(arr: AwsSecurityFinding[], chunkSize: number): AwsSecurityFinding[][] {
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
        return text.replace(/  +/g, ' ').replace(/\r?\n|\r/g, ' ')
    } else {
        return undefined
    }
}

function getTopmostControl(knownControl: Control): Control {
    if(hdf.profiles.length == 1){
        return knownControl
    } 
    let foundControl = undefined
    hdf.profiles[0].controls.forEach((control) => {
        if(control.id === knownControl.id) {
            foundControl = control;
        }
    })
    if(foundControl) {
        return foundControl
    }
    return knownControl;
}

hdf.profiles.forEach((profile) => {
    profile.controls.forEach(async (control) => {
        const topmostControl = getTopmostControl(control)
        control.results.forEach((segment) => {
            // If we passed or failed the subcontrol
            const controlStatus = segment.status == 'passed'
            // Checktext can either be a description or a tag
            const checktext: string = topmostControl.descriptions?.find((description) => description.label === 'check')?.data || topmostControl.tags['check'] as string || 'Check not available'
            // Gets the name of the file inputed
            const filename = options.input.split('/')[options.input.split('/').length - 1]
            const caveat = topmostControl.descriptions?.find((description) => description.label === 'caveat')?.data
            const asffControl: AwsSecurityFinding = {
                SchemaVersion: "2018-10-08",
                Id: `${hdf.profiles[0].name}/${target}/${control.id}/finding/${createHash('sha256').update(control.id + segment.code_desc).digest('hex')}`,
                ProductArn: `arn:aws:securityhub:${options.region}:${options.awsAccountId}:product/${options.awsAccountId}/default`,
                AwsAccountId: options.awsAccountId,
                Types: ["Software and Configuration Checks"],
                CreatedAt: (control.results[0] || {start_time: new Date().toISOString()}).start_time,
                Region: options.region,
                UpdatedAt: new Date().toISOString(),
                GeneratorId: `arn:aws:securityhub:us-east-2:${options.awsAccountId}:ruleset/set/${profile.name}/v1.0.0/rule/${control.id}`,
                Title: _.truncate(`${control.id} | ${topmostControl.tags.nist ? `[${_.get(topmostControl, 'tags.nist').join(', ')}]` : ''} | ${cleanText(topmostControl.title)}`, {length: 256}),
                Description: _.truncate(cleanText(`${topmostControl.desc} -- Check Text: ${checktext}`), {length: 1024}),
                FindingProviderFields: {
                    Severity: {
                        Label: impactMapping.get(topmostControl.impact) || 'INFORMATIONAL',
                        Original: impactMapping.get(topmostControl.impact) || 'INFORMATIONAL'
                    },
                    Types: [`Profile/Name/${profile.name}`, `Profile/Version/${profile.version}`, `Profile/SHA256/${profile.sha256}`, `Profile/Title/${profile.title}`, `Profile/Maintainer/${profile.maintainer}`, `Profile/Summary/${profile.summary}`, `Profile/License/${profile.license}`, `Profile/Copyright/${profile.copyright}`,  `Profile/Copyright Email/${profile.copyright_email}`, `File/Input/${filename}`, `Control/Code/${control.code.replace(/\//g, '')}`]
                },
                Remediation: {
                    Recommendation: {
                        Text: _.truncate(cleanText((topmostControl.descriptions?.find((description) => description.label === 'fix') || {data: topmostControl.fix || 'Fix not available'}).data), {length: 512})
                    }
                },
                ProductFields: {
                    "Check": _.truncate(checktext, {length: 2048})
                },
                Note: {
                    Text: _.truncate(cleanText("Test Description: " + segment.code_desc + " --- Test Result: " + segment.message), {length: 512}),
                    UpdatedAt: new Date().toISOString(),
                    UpdatedBy: 'Test Results',
                },
                Severity: {
                    Label: impactMapping.get(topmostControl.impact) || 'INFORMATIONAL',
                    Original: `${topmostControl.impact}`,
                },
                Resources: [
                    {
                        Type: "AwsAccount",
                        Id: `AWS::::Account:${options.awsAccountId}`,
                        Partition: "aws",
                        Region: options.region
                    },
                    {
                        Id: `${topmostControl.id} Validation Code`,
                        Type: "AwsIamRole",
                        Details: {
                            AwsIamRole: {
                                AssumeRolePolicyDocument: topmostControl.code
                            }
                        }
                    }
                ],
                Compliance: {
                    RelatedRequirements: ['SEE NOTES FOR TEST RESULTS'],
                    Status: controlStatus ? 'PASSED' : 'FAILED',
                    StatusReasons: [
                        {
                            ReasonCode: controlStatus ? 'CONFIG_EVALUATIONS_EMPTY' : 'CLOUDTRAIL_METRIC_FILTER_NOT_VALID',
                            Description:  _.truncate(cleanText(segment.message) || 'Unavailable', {length: 2048})
                        }
                    ]
                }
            }
            for (const tag in topmostControl.tags) {
                if(topmostControl.tags[tag]) {
                    if(tag === 'nist' && Array.isArray(topmostControl.tags.nist)) {
                        asffControl.FindingProviderFields?.Types?.push(`Tags/nist/${topmostControl.tags.nist.join(', ')}`)
                    } else if (tag === 'cci' && Array.isArray(topmostControl.tags.cci)) {
                        asffControl.FindingProviderFields?.Types?.push(`Tags/cci/${topmostControl.tags.cci.join(', ')}`)
                    } else if (typeof topmostControl.tags[tag] === 'string') {
                        asffControl.FindingProviderFields?.Types?.push(`Tags/${tag.replace(/\W/g, '')}/${(topmostControl.tags[tag] as string).replace(/\W/g, '')}`)
                    } else if (typeof topmostControl.tags[tag] === 'object' && Array.isArray(topmostControl.tags[tag])) {
                        asffControl.FindingProviderFields?.Types?.push(`Tags/${tag.replace(/\W/g, '')}/${(topmostControl.tags[tag] as Array<string>).join(', ').replace(/\W/g, '')}`)
                    }
                }
            }
            topmostControl.descriptions?.forEach((description) => {
                if(description.data) {
                    asffControl.FindingProviderFields?.Types?.push(`Descriptions/${description.label.replace(/\W/g, '')}/${cleanText(description.data.replace(/\//, ' or '))?.replace(/[^0-9a-z ]/gi, '')}`)
                }
            })
            if(caveat) {
                asffControl.Description = _.truncate(`Caveat: ${cleanText(caveat)} --- Description: ${asffControl.Description}`, {length: 1024})
                asffControl.Compliance!.StatusReasons![0].Description = _.truncate(`Caveat: ${cleanText(caveat)} --- ${asffControl.Compliance?.StatusReasons![0].Description}`, {length: 2048})
            }
            findings.push(asffControl)
        })
    })
})

// Upload/export the converted controls
try {
    if(options.upload){
        let client = new SecurityHubClient({region: options.region});
        if(options.accessKeyId && options.accessKeySecret) {
            client = new SecurityHubClient({region: options.region, credentials: {accessKeyId: options.accessKeyId, secretAccessKey: options.accessKeySecret}});
        }
        logger.info(`Attempting to upload ${findings.length} findings to Security Hub`)
        sliceIntoChunks(findings, 20).forEach(async (chunk) => {
            const uploadCommand = new BatchImportFindingsCommand({Findings: chunk})
            try {
                const result = await client.send(uploadCommand);
                logger.info(`Uploading ${chunk.length} controls. Success: ${result.SuccessCount}, Fail: ${result.FailedCount}`)
            } catch (err) {
                logger.error(`Failed to upload controls: ${err}`)
            }
        })
    } else {
        sliceIntoChunks(findings, 20).forEach(async (chunk, index) => {
            fs.writeFileSync(`${options.output}.p${index}`, JSON.stringify(chunk))
        })
    }
  } catch (err) {
    logger.error(`Failed to upload controls: ${err}`)
}