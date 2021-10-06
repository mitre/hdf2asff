import { Command } from "commander";
import * as fs from "fs";
import { HDF } from "./types/hdf";
import _ from "lodash";
import { createHash } from "crypto";
import { convertFile, contextualizeEvaluation } from "inspecjs";
import {
  SecurityHubClient,
  BatchImportFindingsCommand,
  AwsSecurityFinding,
} from "@aws-sdk/client-securityhub";
import { createLogger, transports, format } from "winston";
import {
  createDescription,
  getRunTime,
  sliceIntoChunks,
  cleanText,
  getAllLayers,
  createCode,
  createNote,
  statusCount,
  createAssumeRolePolicyDocument,
} from "./helpers";
import moment from 'moment';

const logger = createLogger({
  transports: [
    new transports.Console({
      level: "info",
      format: format.combine(format.colorize(), format.simple()),
    }),
  ],
});

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
program.version("1.0.0");
program
  .requiredOption("-i, --input <infile>", "Input HDF/InSpec JSON")
  .requiredOption("-a, --aws-account-id <accountid>", "AWS Account ID")
  .requiredOption("-r, --region <region>", "AWS Account Region")
  .requiredOption(
    "-t, --target <target>",
    "Name of targeted host (re-use target to preserve findings across time)"
  )
  .option("-o, --output <outfile>", "Output ASFF Findings JSON")
  .option(
    "-u, --upload",
    "Automattically upload findings to Security Hub (AWS CLI must be configured or secrets must be passed)"
  );

program.parse(process.argv);
program.showHelpAfterError();
const options: iOptions = program.opts();

const target = options.target.toLowerCase().trim();
const hdf: HDF = JSON.parse(
  fs.readFileSync(options.input, { encoding: "utf8", flag: "r" })
);
const findings: AwsSecurityFinding[] = [];
const impactMapping: Map<number, string> = new Map([
  [0.9, "CRITICAL"],
  [0.7, "HIGH"],
  [0.5, "MEDIUM"],
  [0.3, "LOW"],
  [0.0, "INFORMATIONAL"],
]);

const inspecJSJson = convertFile(JSON.stringify(hdf));
const profiles = contextualizeEvaluation(inspecJSJson["1_0_ExecJson"] as any);
const counts = statusCount(profiles);

function sleep(milliseconds: number) {
  var start = new Date().getTime();
  for (var i = 0; i < 1e7; i++) {
    if (new Date().getTime() - start > milliseconds) {
      break;
    }
  }
}

// Add results from all profiles
hdf.profiles.forEach((profile) => {
  profile.controls.reverse().forEach((control) => {
    const layersOfControl = getAllLayers(hdf, control);
    control.results.forEach((segment) => {
      // Ensure that the UpdatedAt time is different accross findings (to match the order in HDF)
      sleep(1);
      // If we passed or failed the subcontrol
      const controlStatus =
        segment.status == "skipped"
          ? "WARNING"
          : segment.status == "passed"
          ? "PASSED"
          : "FAILED";
      // Checktext can either be a description or a tag
      const checktext: string =
        layersOfControl[0].descriptions?.find(
          (description) => description.label === "check"
        )?.data ||
        (layersOfControl[0].tags["check"] as string) ||
        "Check not available";
      // Gets the name of the file inputed
      const slashSplit =
        options.input.split("\\")[options.input.split("\\").length - 1];
      const filename = slashSplit.split("/")[slashSplit.split("/").length - 1];
      const caveat = layersOfControl[0].descriptions?.find(
        (description) => description.label === "caveat"
      )?.data;
      const asffControl: AwsSecurityFinding = {
        SchemaVersion: "2018-10-08",
        Id: `${target}/${hdf.profiles[0].name}/${
          control.id
        }/finding/${createHash("sha256")
          .update(control.id + segment.code_desc)
          .digest("hex")}`,
        ProductArn: `arn:aws:securityhub:${options.region}:${options.awsAccountId}:product/${options.awsAccountId}/default`,
        AwsAccountId: options.awsAccountId,
        Types: ["Software and Configuration Checks"],
        CreatedAt: (
          control.results[0] || { start_time: new Date().toISOString() }
        ).start_time,
        Region: options.region,
        UpdatedAt: new Date().toISOString(),
        GeneratorId: `arn:aws:securityhub:us-east-2:${options.awsAccountId}:ruleset/set/${hdf.profiles[0].name}/rule/${control.id}`,
        Title: _.truncate(
          `${control.id} | ${
            layersOfControl[0].tags.nist
              ? `[${_.get(layersOfControl[0], "tags.nist").join(", ")}]`
              : ""
          } | ${cleanText(layersOfControl[0].title)}`,
          { length: 256 }
        ),
        Description: _.truncate(
          cleanText(`${layersOfControl[0].desc} -- Check Text: ${checktext}`),
          { length: 1024, omission: '[SEE FULL TEXT IN AssumeRolePolicyDocument]' }
        ),
        FindingProviderFields: {
          Severity: {
            Label:
              impactMapping.get(layersOfControl[0].impact) || "INFORMATIONAL",
            Original:
              impactMapping.get(layersOfControl[0].impact) || "INFORMATIONAL",
          },
          Types: [
            `File/Input/${filename}`,
            `Control/Code/${control.code.replace(/\//g, "∕")}`,
          ],
        },
        Remediation: {
          Recommendation: {
            Text: _.truncate(
              cleanText(
                createNote(segment) + " --- Fix: " +
                  (
                    layersOfControl[0].descriptions?.find(
                      (description) => description.label === "fix"
                    ) || {
                      data: layersOfControl[0].fix || "Fix not available",
                    }
                  ).data
              ),
              { length: 512, omission: '... [SEE FULL TEXT IN AssumeRolePolicyDocument]' }
            ),
          },
        },
        ProductFields: {
          Check: _.truncate(checktext, { length: 2048, omission: '' }),
        },
        Severity: {
          Label:
            impactMapping.get(layersOfControl[0].impact) || "INFORMATIONAL",
          Original: `${layersOfControl[0].impact}`,
        },
        Resources: [
          {
            Type: "AwsAccount",
            Id: `AWS::::Account:${options.awsAccountId}`,
            Partition: "aws",
            Region: options.region,
          },
          {
            Id: `${layersOfControl[0].id} Validation Code`,
            Type: "AwsIamRole",
            Details: {
              AwsIamRole: {
                AssumeRolePolicyDocument: createAssumeRolePolicyDocument(layersOfControl, segment)
              },
            },
          },
        ],
        Compliance: {
          RelatedRequirements: ["SEE REMEDIATION FIELD FOR RESULTS AND RECOMMENDED ACTION(S)"],
          Status: controlStatus,
          StatusReasons: []
        },
      };
      if(segment.message) {
          asffControl.Compliance?.StatusReasons?.push({
            ReasonCode: "CONFIG_EVALUATIONS_EMPTY",
            Description: _.truncate(
              cleanText(segment.message) || "Unavailable",
              { length: 2048, omission: '' }
            ),
          })
      }
      // Add all layers of profile info to the Finding Provider Fields
      let targets = ['name', 'version', 'sha256', 'title', 'maintainer', 'summary', 'license', 'copyright', 'copyright_email']
      layersOfControl.forEach((layer) => {
        const profileInfos: Record<string, string>[] = []
        targets.forEach((target) => {
          const value = _.get(layer.profileInfo, target);
          if (typeof value === "string" && value) {
            profileInfos.push({[target]: value})
          }
        });
        asffControl.FindingProviderFields?.Types?.push(`Profile/Info/${JSON.stringify(profileInfos).replace(/\//g, '∕')}`);
      })
      // Add segment/result information to Finding Provider Fields
      targets = [
        "code_desc",
        "exception",
        "message",
        "resource",
        "run_time",
        "start_time",
        "skip_message",
        "status"
      ];
      targets.forEach((target) => {
        const value = _.get(segment, target);
        if (typeof value === "string" && value) {
          asffControl.FindingProviderFields?.Types?.push(
            `Segment/${target}/${value.replace(/\//g, '∕')}`
          );
        }
      });
      // Add Tags to Finding Provider Fields
      for (const tag in layersOfControl[0].tags) {
        if (layersOfControl[0].tags[tag]) {
          if (tag === "nist" && Array.isArray(layersOfControl[0].tags.nist)) {
            asffControl.FindingProviderFields?.Types?.push(
              `Tags/nist/${layersOfControl[0].tags.nist.join(", ")}`
            );
          } else if (
            tag === "cci" &&
            Array.isArray(layersOfControl[0].tags.cci)
          ) {
            asffControl.FindingProviderFields?.Types?.push(
              `Tags/cci/${layersOfControl[0].tags.cci.join(", ")}`
            );
          } else if (typeof layersOfControl[0].tags[tag] === "string") {
            asffControl.FindingProviderFields?.Types?.push(
              `Tags/${tag.replace(/\W/g, "")}/${(
                layersOfControl[0].tags[tag] as string
              ).replace(/\W/g, "")}`
            );
          } else if (
            typeof layersOfControl[0].tags[tag] === "object" &&
            Array.isArray(layersOfControl[0].tags[tag])
          ) {
            asffControl.FindingProviderFields?.Types?.push(
              `Tags/${tag.replace(/\W/g, "")}/${(
                layersOfControl[0].tags[tag] as Array<string>
              )
                .join(", ")
                .replace(/\W/g, "")}`
            );
          }
        }
      }
      // Add Descriptions to FindingProviderFields
      layersOfControl[0].descriptions?.forEach((description) => {
        if (description.data) {
          asffControl.FindingProviderFields?.Types?.push(
            `Descriptions/${description.label.replace(/\W/g, "")}/${cleanText(
              description.data.replace(/\//, "∕")
            )?.replace(/[^0-9a-z ]/gi, "")}`
          );
        }
      });
      if (caveat) {
        asffControl.Description = _.truncate(
          `Caveat: ${cleanText(caveat)} --- Description: ${
            asffControl.Description
          }`,
          { length: 1024, omission: '' }
        );
      }
      findings.push(asffControl);
    });
  });
});

const runTime = getRunTime(hdf);
// Add a finding that gives information on the results set
const profileInfo: AwsSecurityFinding = {
  SchemaVersion: "2018-10-08",
  Id: `${target}/${hdf.profiles[0].name}`,
  ProductArn: `arn:aws:securityhub:${options.region}:${options.awsAccountId}:product/${options.awsAccountId}/default`,
  GeneratorId: `arn:aws:securityhub:us-east-2:${options.awsAccountId}:ruleset/set/${hdf.profiles[0].name}`,
  AwsAccountId: options.awsAccountId,
  CreatedAt: runTime.toISOString(),
  UpdatedAt: new Date().toISOString(),
  Title: `${target} | ${
    hdf.profiles[0].name
  } | ${moment().format('YYYY-MM-DD hh:mm:ss [GMT]ZZ')}`,
  Description: createDescription(counts),
  Severity: {
    Label: "INFORMATIONAL",
  },
  FindingProviderFields: {
    Severity: {
      Label: "INFORMATIONAL",
    },
    Types: [],
  },
  Resources: [
    {
      Type: "AwsAccount",
      Id: `AWS::::Account:${options.awsAccountId}`,
      Partition: "aws",
      Region: options.region,
    },
  ],
};
const profileInfoFindings: AwsSecurityFinding[] = [];

hdf.profiles.forEach((profile) => {
  const targets = [
    "version",
    "sha256",
    "maintainer",
    "summary",
    "license",
    "copyright",
    "copyright_email",
  ];
  targets.forEach((target) => {
    const value = _.get(profile, target);
    if (typeof value === "string") {
      profileInfo.FindingProviderFields?.Types?.push(
        `${profile.name}/${target}/${value}`
      );
    }
  });
  const inputs: Record<string, unknown>[] = [];
  profile.attributes.forEach((input) => {
    if (input.options.value) {
      inputs.push({ [input.name]: input.options.value });
    }
  });
  profileInfo.FindingProviderFields?.Types?.push(
    `${profile.name}/inputs/${JSON.stringify(inputs).replace(/\//g, "∕")}`
  );
});
profileInfo.FindingProviderFields!.Types =
  profileInfo.FindingProviderFields?.Types?.slice(0, 50);

profileInfoFindings.push(profileInfo);

// Upload/export the converted controls
try {
  if (options.upload) {
    let client = new SecurityHubClient({ region: options.region });
    logger.info(
      `Attempting to upload ${findings.length} findings to Security Hub`
    );
    Promise.all(
      sliceIntoChunks(findings, 100).map(async (chunk) => {
        const uploadCommand = new BatchImportFindingsCommand({
          Findings: chunk,
        });
        try {
          const result = await client.send(uploadCommand);
          logger.info(
            `Uploaded ${chunk.length} controls. Success: ${result.SuccessCount}, Fail: ${result.FailedCount}`
          );
          if(result.FailedFindings?.length) {
            logger.error(`Failed to upload ${result.FailedCount} Findings`)
            console.log(result.FailedFindings)
        }
        } catch (err) {
          logger.error(`Failed to upload controls: ${err}`);
        }
      })
    ).then(() => {
      profileInfoFindings.forEach(async (finding) => {
        finding.UpdatedAt = new Date().toISOString();
        const profileInfoUploadCommand = new BatchImportFindingsCommand({
          Findings: [finding],
        });
        const result = await client.send(profileInfoUploadCommand);
        logger.info(`Statistics: ${finding.Description}`);
        logger.info(
          `Uploaded Results Set Info Finding(s) - Success: ${result.SuccessCount}, Fail: ${result.FailedCount}`
        );
        if(result.FailedFindings?.length) {
            logger.error(`Failed to upload ${result.FailedCount} Results Set Info Finding`)
            console.log(result.FailedFindings)
        }
      });
    });
  }
  if (options.output) {
    sliceIntoChunks(findings, 20).forEach(async (chunk, index) => {
      fs.writeFileSync(
        `${options.output}.p${index}.json`,
        JSON.stringify(chunk)
      );
    });
  }
  if (!options.upload && !options.output) {
    logger.error(
      `You have not provided an output path or enabled auto-upload. Please use -o <path> to output files or -u to upload files to Security Hub. Use -h for more help.`
    );
  }
} catch (err) {
  logger.error(`Failed to upload controls: ${err}`);
}
