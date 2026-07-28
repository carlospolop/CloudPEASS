import subprocess
import re
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from tqdm import tqdm
import shutil

from colorama import Fore, init


class AWSBruteForce():

    def __init__(self, debug, region, profile, aws_services, threads, access_key_id=None, secret_access_key=None, session_token=None):
        self.debug = debug
        self.region = region
        self.profile = profile
        self.aws_services = [a.lower() for a in aws_services]
        self.num_threads = threads
        self.found_permissions = []
        self.lock = threading.Lock()
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session_token = session_token

        if shutil.which("aws") is None:
            print("AWS CLI is not installed or not in PATH. Please install the AWS CLI before running this tool.")
            exit(1)

    # Utility functions
    def transform_command(self, command):
        substitutions = [
            (r'accessanalizer', 'access-analyzer'),
            (r'amp:', 'aps:'),
            (r'apigateway:Get.*', 'apigateway:GET'),
            (r'apigatewayv2:Get.*', 'apigateway:GET'),
            (r'appintegrations:', 'app-integrations:'),
            (r'application-insights:', 'applicationinsights:'),
            (r'athena:ListApplicationDpuSizes', 'athena:ListApplicationDPUSizes'),
            (r'chime-.*:', 'chime:'),
            (r'cloudcontrol:', 'cloudformation:'),
            (r'cloudfront:ListDistributionsByWebAclId', 'cloudfront:ListDistributionsByWebACLId'),
            (r'cloudhsmv2:', 'cloudhsm:'),
            (r'codeguruprofiler:', 'codeguru-profiler:'),
            (r'comprehendmedical:ListIcd10CmInferenceJobs', 'comprehendmedical:ListICD10CMInferenceJobs'),
            (r'comprehendmedical:ListPhiDetectionJobs', 'comprehendmedical:ListPHIDetectionJobs'),
            (r'comprehendmedical:ListSnomedctInferenceJobs', 'comprehendmedical:ListSNOMEDCTInferenceJobs'),
            (r'configservice:', 'config:'),
            (r'connectcampaigns:', 'connect-campaigns:'),
            (r'connectcases:', 'cases:'),
            (r'customer-profiles:', 'profile:'),
            (r'deploy:', 'codeploy:'),
            (r'detective:ListOrganizationAdminAccounts', 'detective:ListOrganizationAdminAccount'),
            (r'docdb:', 'rds:'),
            (r'dynamodbstreams:', 'dynamodb:'),
            (r'ecr:GetLoginPassword', 'ecr:GetAuthorizationToken'),
            (r'efs:', 'elasticfilesystem:'),
            (r'elbv2', 'elasticloadbalancing:'),
            (r'elb:', 'elasticloadbalancing:'),
            (r'emr:', 'elasticmapreduce:'),
            (r'frauddetector:GetKmsEncryptionKey', 'frauddetector:GetKMSEncryptionKey'),
            (r'gamelift:DescribeEc2InstanceLimits', 'gamelift:DescribeEC2InstanceLimits'),
            (r'glue:GetMlTransforms', 'glue:GetMLTransforms'),
            (r'glue:ListMlTransforms', 'glue:ListMLTransforms'),
            (r'greengrassv2:', 'greengrass:'),
            (r'healthlake:ListFhirDatastores', 'healthlake:ListFHIRDatastores'),
            (r'iam:ListMfaDevices', 'iam:ListMFADevices'),
            (r'iam:ListOpenIdConnectProviders', 'iam:ListOpenIDConnectProviders'),
            (r'iam:ListSamlProviders', 'iam:ListSAMLProviders'),
            (r'iam:ListSshPublicKeys', 'iam:ListSSHPublicKeys'),
            (r'iam:ListVirtualMfaDevices', 'iam:ListVirtualMFADevices'),
            (r'iot:ListCaCertificates', 'iot:ListCACertificates'),
            (r'iot:ListOtaUpdates', 'iot:ListOTAUpdates'),
            (r'iot-data:', 'iot:'),
            (r'iotsecuretunneling:', 'iot:'),
            (r'ivs-realtime:', 'ivs:'),
            (r'kinesis-video-archived-media:', 'kinesisvideo:'),
            (r'kinesis-video-signaling:', 'kinesisvideo:'),
            (r'kinesisanalyticsv2:', 'kinesisanalytics:'),
            (r'lakeformation:ListLfTags', 'lakeformation:ListLFTags'),
            (r'lex-models:', 'lex:'),
            (r'lexv2-models:', 'lex:'),
            (r'lightsail:GetContainerApiMetadata', 'lightsail:GetContainerAPIMetadata'),
            (r'location:', 'geo:'),
            (r'marketplace-entitlement:', 'aws-marketplace:'),
            (r'migration-hub-refactor-spaces:', 'refactor-spaces:'),
            (r'migrationhub-config:', 'mgh:'),
            (r'migrationhuborchestrator:', 'migrationhub-orchestrator:'),
            (r'migrationhubstrategy:', 'migrationhub-strategy:'),
            (r'mwaa:', 'airflow:'),
            (r'neptune:', 'rds:'),
            (r'network-firewall:ListTlsInspectionConfigurations', 'network-firewall:ListTLSInspectionConfigurations'),
            (r'opensearch:', 'es:'),
            (r'opensearchserverless:', 'aoss:'),
            (r'organizations:ListAwsServiceAccessForOrganization', 'organizations:ListAWSServiceAccessForOrganization'),
            (r'pinpoint:', 'mobiletargeting:'),
            (r'pinpoint-email:', 'ses:'),
            (r'pinpoint-sms-voice-v2:', 'sms-voice:'),
            (r'privatenetworks:', 'private-networks:'),
            (r'Db', 'DB'),
            (r'resourcegroupstaggingapi:', 'tag:'),
            (r's3outposts:', 's3-outposts:'),
            (r'sagemaker:ListAutoMlJobs', 'sagemaker:ListAutoMLJobs'),
            (r'sagemaker:ListCandidatesForAutoMlJob', 'sagemaker:ListCandidatesForAutoMLJob'),
            (r'service-quotas:', 'servicequotas:'),
            (r'servicecatalog:GetAwsOrganizationsAccessStatus', 'servicecatalog:GetAWSOrganizationsAccessStatus'),
            (r'servicecatalog-appregistry:', 'servicecatalog:'),
            (r'sesv2:', 'ses:'),
            (r'sns:GetSmsAttributes', 'sns:GetSMSAttributes'),
            (r'sns:GetSmsSandboxAccountStatus', 'sns:GetSMSSandboxAccountStatus'),
            (r'sns:ListSmsSandboxPhoneNumbers', 'sns:ListSMSSandboxPhoneNumbers'),
            (r'sso-admin:', 'sso:'),
            (r'stepfunctions:', 'states:'),
            (r'support-app:', 'supportapp:'),
            (r'timestream-query:', 'timestream:'),
            (r'timestream-write:', 'timestream:'),
            (r'voice-id:', 'voiceid:'),
            (r'waf:ListIpSets', 'waf:ListIPSets'),
            (r'waf:ListWebAcls', 'waf:ListWebACLs'),
            (r'waf-regional:ListIpSets', 'waf-regional:ListIPSets'),
            (r'waf-regional:ListWebAcls', 'waf-regional:ListWebACLs'),
            (r'keyspaces:ListKeyspaces', 'cassandra:Select'),
            (r'keyspaces:ListTables', 'cassandra:Select'),
            (r's3api:ListBuckets', 's3:ListAllMyBuckets')
        ]

        for pattern, replacement in substitutions:
            command = re.sub(pattern, replacement, command)

        return command

    def capitalize(self, command):
        return ''.join(word.capitalize() for word in command.split('-'))

    def _build_command(self, profile, region, service, command, extra):
        if profile:
            base = f'aws --cli-connect-timeout 19 --profile {profile} --region {region} {service} {command} {extra}'
        else:
            base = f'aws --cli-connect-timeout 19 --region {region} {service} {command} {extra}'
        return base.strip()

    def _build_env(self, profile):
        if profile:
            return None
        env = os.environ.copy()
        for var_name in (
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CONFIG_FILE",
            "AWS_SDK_LOAD_CONFIG",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "AWS_ROLE_ARN",
            "AWS_ROLE_SESSION_NAME",
            "AWS_CREDENTIAL_EXPIRATION",
            "AWS_SECURITY_TOKEN",
        ):
            env.pop(var_name, None)
        if self.access_key_id:
            env['AWS_ACCESS_KEY_ID'] = self.access_key_id
        if self.secret_access_key:
            env['AWS_SECRET_ACCESS_KEY'] = self.secret_access_key
        if self.session_token:
            env['AWS_SESSION_TOKEN'] = self.session_token
        else:
            env.pop("AWS_SESSION_TOKEN", None)
        env["AWS_EC2_METADATA_DISABLED"] = "true"
        return env

    def _get_aws_help(self, service=None):
        env = os.environ.copy()
        # AWS CLI help may inherit an interactive pager from the user's shell.
        # Force plain output so help parsing behaves consistently across systems.
        env["AWS_PAGER"] = ""
        env["PAGER"] = "cat"
        env["MANPAGER"] = "cat"

        command = ["aws"]
        if service:
            command.append(service)
        command.append("help")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=30,
                env=env,
            )
        except subprocess.TimeoutExpired:
            if self.debug:
                print(f"[DEBUG] Timed out while running: {' '.join(command)}")
            return []

        if result.returncode != 0:
            if self.debug:
                error = result.stderr.decode(errors="replace").strip()
                print(f"[DEBUG] Failed to run {' '.join(command)}: {error}")
            return []

        output = result.stdout
        if shutil.which("col"):
            col_result = subprocess.run(
                ["col", "-b"],
                input=output,
                capture_output=True,
            )
            if col_result.returncode == 0:
                output = col_result.stdout

        return output.decode(errors="replace").splitlines()

    def run_command(self, profile, region, service, command, extra='', cont=0):
        full_command = self._build_command(profile, region, service, command, extra)
        env = self._build_env(profile)
        
        try:
            result = subprocess.run(full_command, shell=True, capture_output=True, timeout=20, env=env)
            output = result.stdout.decode() + result.stderr.decode()

            if result.returncode == 0 or re.search(r'NoSuchEntity|ResourceNotFoundException|NotFoundException', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Successful or resource not found: {output.strip()}")
                perm_command = self.transform_command(f"{service}:{self.capitalize(command)}")
                print(f"{Fore.YELLOW}[+] {Fore.WHITE}You can access: {Fore.YELLOW}{service} {command} {Fore.BLUE}({full_command}) {Fore.GREEN}({perm_command}){Fore.RESET}")
                
                with self.lock:
                    self.found_permissions.append(perm_command)

            elif re.search(r'AccessDenied|ForbiddenException|UnauthorizedOperation|UnsupportedCommandException|AuthorizationException', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Access denied for: {full_command}")

            elif re.search(r'ValidationException|ValidationError|InvalidArnException|InvalidRequestException|InvalidParameterValueException|InvalidARNFault|Invalid ARN|InvalidIpamScopeId.Malformed|InvalidParameterException|invalid literal for', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Validation error for: {full_command}")

            elif re.search(r'Could not connect to the endpoint URL', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Could not connect to endpoint: {full_command}")

            elif re.search(r'Unknown options|MissingParameter|InvalidInputException|error: argument', output, re.I):
                if self.debug:
                    print(f"[DEBUG] Option error for: {full_command}")

            elif re.search(r'arguments are required', output, re.I):
                required_arg_match = re.search(r'arguments are required: ([^\s,]+)', output)
                if required_arg_match:
                    required_arg = required_arg_match.group(1)
                    name_string = "OrganizationAccountAccessRole"
                    arn_string = f"arn:aws:iam::123456789012:role/{name_string}"

                    test_extra = f"{extra} {required_arg} {name_string}".strip()
                    test_cmd = self._build_command(profile, region, service, command, test_extra)
                    test_result = subprocess.run(test_cmd, shell=True, capture_output=True, timeout=20, env=env)
                    test_output = test_result.stdout.decode() + test_result.stderr.decode()

                    if re.search(r'ValidationException|ValidationError|InvalidArnException|InvalidRequestException|InvalidParameterValueException|InvalidARNFault|Invalid ARN|InvalidIpamScopeId.Malformed|InvalidParameterException|invalid literal for', test_output, re.I):
                        extra = f"{extra} {required_arg} {arn_string}".strip()
                    else:
                        extra = f"{extra} {required_arg} {name_string}".strip()
                    
                    if cont < 3:
                        self.run_command(profile, region, service, command, extra, cont+1)
                    else:
                        if self.debug:
                            print(f"[DEBUG] Prevented eternal loop of args from: {command}\n{output.strip()}")

            else:
                if self.debug:
                    print(f"[DEBUG] Unhandled response for: {full_command}\n{output.strip()}")

        except subprocess.TimeoutExpired:
            if self.debug:
                print(f"[DEBUG] Command timed out: {full_command}")
            print(f"[-] Timeout: {full_command}")

    def get_aws_services(self):
        output = self._get_aws_help()
        start_string = "AVAILABLE SERVICES"
        end_string = "SEE ALSO"
        point = "o"
        in_range = False
        services = []

        for line in output:
            line = line.strip()
            if start_string in line.upper():
                in_range = True
            elif end_string in line.upper():
                in_range = False

            if in_range and line and line != point and start_string not in line:
                if line.startswith("o "):
                    line = line[2:]
                services.append(line)

        return services

    def get_commands_for_service(self, service):
        output = self._get_aws_help(service)
        start_string = "AVAILABLE COMMANDS"
        end_string = "SEE ALSO"
        in_range = False
        commands = []

        for line in output:
            line = line.strip()
            if start_string in line.upper():
                in_range = True
            elif end_string in line.upper():
                in_range = False

            if in_range and line:
                if line.startswith("o "):
                    line = line[2:]
                if re.match(r'^(list|ls|describe|get)', line):
                    commands.append(line)

        return commands

    def brute_force_permissions(self):
        commands_to_run = []
        print(f"{Fore.GREEN}Starting permission enumeration...")

        services = self.get_aws_services()

        if self.aws_services:
            filterred_services = [service for service in services if service.lower() in self.aws_services ]
            if not filterred_services:
                print(f"{Fore.RED}No services found to test. Please check your input because you probably misspelled the filtering. Exiting...{Fore.RESET}")
                return []
            else:
                print(f"{Fore.YELLOW}Filtered services to bf: {', '.join(filterred_services)}{Fore.RESET}")

        else:
            filterred_services = services

        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            future_to_service = {
                executor.submit(self.get_commands_for_service, service): service 
                for service in filterred_services
            }
            pbar = tqdm(total=len(future_to_service), desc="Getting commands to test")
            for future in as_completed(future_to_service):
                pbar.update(1)
                service = future_to_service[future]
                try:
                    commands = future.result(timeout=30)
                    for command in commands:
                        commands_to_run.append((self.profile, self.region, service, command))
                except TimeoutError:
                    if self.debug:
                        print(f"[DEBUG] Timeout getting commands for {service}")
                except Exception as e:
                    if self.debug:
                        print(f"[DEBUG] Failed to get commands for {service}: {e}")
            pbar.close()

        if not commands_to_run:
            print(
                f"{Fore.RED}No AWS CLI commands were discovered. "
                "Unable to brute-force permissions. Run with --debug to check "
                f"the AWS CLI help output.{Fore.RESET}"
            )
            return []

        with ThreadPoolExecutor(max_workers=self.num_threads*4) as executor:
            futures = [executor.submit(self.run_command, *args) for args in commands_to_run]
            pbar = tqdm(total=len(futures), desc="Running commands")
            for future in as_completed(futures):
                pbar.update(1)
            pbar.close()

        print("\n[+] Permission enumeration completed.")
        return self.found_permissions
