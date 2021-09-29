# hdf2ASFF
This tool converts and uploads Heimdall Data Format (HDF) into Amazon Security Findings Format (ASFF).

----



## How to Install:

**Windows/Linux/MacOS:**

1. Clone the repository: `git clone https://github.com/mitre/hdf2asff`
2. Install dependencies: `yarn install`
3. Build the app: `yarn run build`

**Windows:**

1. Download and extract the most recent version from [here](https://github.com/mitre/ckl2POAM/archive/refs/heads/main.zip).
2. Lower your PowerShell Execution Policy with `Set-Executionpolicy Unrestricted` (Press Win+X and choose Open PowerShell as Administrator)
3. Open `setup.ps1` 
   - If you encounter an error running this script try running `Unblock-File -Path C:\path\to\setup.ps1` in PowerShell
4. Follow the on-screen steps to install NodeJS and build the app
5. Restore PowerShell Execution policy with `Set-Executionpolicy Default`

---



## How to Use:

1. Open CMD/Powershell/Terminal and enter the directory of hdf2ASFF
   - Windows Shortcut: Shift + Right Click inside folder
   - Mac Shortcut: Right-Click hdf2ASFF folder from parent directory -> Services -> New Terminal at Folder
2. Start the program with `yarn start`. Some examples:
   - To convert and upload controls using credentials setup in the AWS CLI:
   
     - `yarn start --input <path/to/input.json> --aws-account-id <AWS Account ID> --region <Security Hub Region> --target <Target Name> --upload`
   - To convert and upload controls using specific credentials:
   
     - `yarn start --input <path/to/input.json> --aws-account-id <AWS Account ID> --access-key <AWS IAM Access Key> --access-key-secret <AWS IAM Access Key Secret> --region <Security Hub Region> --target <Target Name> --upload`

---



## Usage

```Usage: index [options]
  -V, --version                              output the version number
  -i, --input <infile>                       Input HDF/InSpec JSON
  -a, --aws-account-id <accountid>           AWS Account ID
  -r, --region <region>                      AWS Account Region
  -t, --target <target>                      Name of targeted host (re-use target to preserve findings across time)
  -a, --access-key <accessKeyId>
  -a, --access-key-secret <accessKeySecret>
  -o, --output <outfile>                     Output ASFF Findings JSON
  -u, --upload                               Automattically upload findings to Security Hub (AWS CLI must be configured or secrets must be passed)
  -h, --help                                 display help for command
