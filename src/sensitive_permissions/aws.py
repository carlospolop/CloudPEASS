

very_sensitive_combinations = [
    ["[*]"],
    ["iam:PassRole"],

    ["codebuild:StartBuild"],
    ["codebuild:StartBuildBatch"],

    ["cognito-identity:UpdateIdentityPool"],
    ["cognito-idp:AdminAddUserToGroup"],
    ["cognito-idp:AdminConfirmSignUp"],
    ["cognito-idp:AdminCreateUser"],
    ["cognito-idp:AdminSetUserPassword"],
    ["cognito-idp:SetUserPoolMfaConfig"],
    ["cognito-idp:UpdateUserPool"],
    ["cognito-idp:AdminUpdateUserAttributes"],
    ["cognito-idp:CreateUserPoolClient"],
    ["cognito-idp:UpdateUserPoolClient"],
    ["cognito-idp:CreateUserImportJob"],
    ["cognito-idp:StartUserImportJob"],
    ["cognito-idp:CreateIdentityProvider"],
    ["cognito-idp:UpdateIdentityProvider"],

    ["ds:ResetUserPassword"],

    ["dynamodb:PutResourcePolicy"],

    ["ec2:ModifyInstanceAttribute"],
    ["ec2:CreateLaunchTemplateVersion", "ec2:CreateLaunchTemplate", "ec2:ModifyLaunchTemplate"],
    ["ec2-instance-connect:SendSSHPublicKey"],
    ["ec2-instance-connect:SendSerialConsoleSSHPublicKey"],

    ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:CompleteLayerUpload", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart"],
    ["ecr-public:GetAuthorizationToken", "ecr-public:BatchCheckLayerAvailability", "ecr-public:CompleteLayerUpload", "ecr-public:InitiateLayerUpload", "ecr-public:PutImage", "ecr-public:UploadLayerPart"],
    ["ecr:SetRepositoryPolicy"],
    ["ecr-public:SetRepositoryPolicy"],
    ["ecr:PutRegistryPolicy"],

    ["ecs:RegisterTaskDefinition"],
    ["ecs:ExecuteCommand"],

    ["elasticfilesystem:DeleteFileSystemPolicy"],
    ["elasticfilesystem:PutFileSystemPolicy"],

    ["elasticmapreduce:OpenEditorInConsole"],

    ["gamelift:RequestUploadCredentials"],

    ["glue:UpdateDevEndpoint"],
    ["glue:UpdateJob"],

    ["iam:CreatePolicyVersion"],
    ["iam:SetDefaultPolicyVersion"],
    ["iam:CreateAccessKey"],
    ["iam:CreateLoginProfile"],
    ["iam:UpdateLoginProfile"],
    ["iam:UpdateAccessKey"],
    ["iam:CreateServiceSpecificCredential"],
    ["iam:ResetServiceSpecificCredential"],
    ["iam:AttachUserPolicy"],
    ["iam:AttachGroupPolicy"],
    ["iam:AttachRolePolicy"],
    ["iam:PutUserPolicy"],
    ["iam:PutGroupPolicy"],
    ["iam:PutRolePolicy"],
    ["iam:AddUserToGroup"],
    ["iam:UpdateAssumeRolePolicy"],
    ["iam:UploadSSHPublicKey"],
    ["iam:DeactivateMFADevice"],
    ["iam:ResyncMFADevice"],
    ["iam:UpdateSAMLProvider"],
    ["iam:UpdateOpenIDConnectProviderThumbprint"],

    ["kms:PutKeyPolicy"],
    ["kms:CreateGrant"],

    ["lambda:AddPermission"],
    ["lambda:AddLayerVersionPermission"],
    ["lambda:UpdateFunctionCode"],

    ["lightsail:DownloadDefaultKeyPair"],
    ["lightsail:GetInstanceAccessDetails"],
    ["lightsail:CreateBucketAccessKey"],
    ["lightsail:GetRelationalDatabaseMasterUserPassword"],
    ["lightsail:UpdateRelationalDatabase"],
    ["lightsail:OpenInstancePublicPorts"],
    ["lightsail:PutInstancePublicPorts"],
    ["lightsail:SetResourceAccessForBucket"],
    ["lightsail:UpdateBucket"],
    ["lightsail:UpdateContainerService"],
    ["lightsail:UpdateDomainEntry"],
    ["lightsail:CreateDomainEntry"],

    ["mediapackage:RotateChannelCredentials"],
    ["mediapackage:RotateIngestEndpointCredentials"],

    ["mq:CreateUser"],
    ["mq:UpdateUser"],
    ["mq:UpdateBroker"],

    ["kafka:UpdateSecurity"],

    ["rds:ModifyDBInstance"],

    ["redshift:DescribeClusters", "redshift:GetClusterCredentials"],

    ["redshift:DescribeClusters", "redshift:GetClusterCredentialsWithIAM"],

    ["route53:CreateHostedZone", "route53:ChangeResourceRecordSets", "acm-pca:IssueCertificate",  "acm-pca:GetCertificate"],

    ["sns:AddPermission"],

    ["sqs:AddPermission"],

    ["identitystore:CreateGroupMembership"],
    ["sso:PutInlinePolicyToPermissionSet", "sso:ProvisionPermissionSet"],
    ["sso:AttachManagedPolicyToPermissionSet", "sso:ProvisionPermissionSet"],
    ["sso:AttachCustomerManagedPolicyReferenceToPermissionSet", "sso:ProvisionPermissionSet"],
    ["sso:CreateAccountAssignment"],

    ["s3:PutBucketPolicy"],
    ["s3:PutBucketAcl"],
    ["s3:PutObjectAcl"],
    ["s3:PutObjectVersionAcl"],

    ["sagemaker:CreatePresignedNotebookInstanceUrl"],

    ["secretsmanager:GetSecretValue"],
    ["secretsmanager:PutResourcePolicy"],

    ["ssm:SendCommand"],
    ["ssm:StartSession"],
    ["ssm:ResumeSession"],

    ["states:UpdateStateMachine"],

    ["sts:AssumeRole"],
    ["sts:AssumeRoleWithSAML"],
    ["sts:AssumeRoleWithWebIdentity"],
    ["codeartifact:GetAuthorizationToken", "sts:GetServiceBearerToken"]
]

sensitive_combinations = [
    ["account:GetContactInformation"],
    ["amplify:GetApp"],
    ["amplify:GetJob"],
    ["cloudfront:GetFunction"],
    ["cloudtrail:LookupEvents"],
    ["ce:GetCostAndUsage"],
    ["cloudfront:GetDistribution"],
    ["cloudfront:GetDistributionConfig"],
    ["cloudfront:ListDistributions"],
    ["codebuild:BatchGetBuilds"],
    ["codebuild:BatchGetProjects"],
    ["codecommit:GetBlob"],
    ["codecommit:GetCommit"],
    ["codecommit:GetFile"],
    ["codecommit:GitPull"],
    ["cognito-idp:AdminGetUser"],
    ["cognito-idp:DescribeIdentityProvider"],
    ["cognito-idp:ListUsers"],
    ["cognito-idp:ListUsersInGroup"],
    ["dynamodb:TransactGetItems"],
    ["ec2:DescribeLaunchTemplateVersions"],
    ["ecr:GetDownloadUrlForLayer"],
    ["ecs:DescribeTaskDefinition"],
    ["lambda:GetFunctionConfiguration"],
    ["lambda:GetLayerVersion"],
    ["logs:FilterLogEvents"],
    ["logs:GetLogEvents"],
    ["invoicing:BatchGetInvoiceProfile"],
    ["invoicing:GetInvoicePDF"],
    ["invoicing:ListInvoiceSummaries"],
    ["lambda:GetFunction"],
    ["route53domains:GetDomainDetail"],
    ["sagemaker:DescribeTrainingJob"],
    ["ses:GetSuppressedDestination"],
    ["ses:ListSuppressedDestinations"],
    ["sns:ListSubscriptions"],
    ["sns:ListSubscriptionsByTopic"],
    ["ssm:GetParameterHistory"],
    ["sts:GetFederationToken"],
    ["tax:GetTaxRegistration"],
    ["tax:ListTaxRegistrations"],

    ["apigateway:POST"],
    ["apigateway:GET"],
    ["apigateway:PUT"],
    ["apigateway:PATCH"],
    ["apigateway:UpdateRestApiPolicy"],

    ["chime:CreateApiKey"],

    ["codebuild:CreateProject"],
    ["codebuild:UpdateProject"],

    ["s3:GetObject"],
    ["s3:PutObject"],

    ["codepipeline:CreatePipeline", "codebuild:CreateProject", "codepipeline:StartPipelineExecution"],
    ["codepipeline:PollForJobs"],

    ["codestar:CreateProject"],

    ["cloudformation:CreateStack"],
    ["cloudformation:UpdateStack"],
    ["cloudformation:UpdateStackSet"],
    ["cloudformation:SetStackPolicy"],
    ["cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet"],

    ["cognito-identity:SetIdentityPoolRoles"],
    ["cognito-idp:CreateGroup", "cognito-idp:UpdateGroup"],
    ["cognito-idp:AdminEnableUser"],
    ["cognito-idp:AdminInitiateAuth"], 
    ["cognito-idp:AdminRespondToAuthChallenge"],

    ["datapipeline:CreatePipeline"],
    ["datapipeline:PutPipelineDefinition"],
    ["datapipeline:ActivatePipeline"],

    ["dynamodb:BatchGetItem"],
    ["dynamodb:GetItem"],
    ["dynamodb:Query"],
    ["dynamodb:Scan"],
    ["dynamodb:PartiQLSelect"],
    ["dynamodb:ExportTableToPointInTime"],
    ["dynamodb:RestoreTableFromBackup"],
    ["dynamodb:PutItem"],
    ["dynamodb:UpdateItem"],

    ["ebs:ListSnapshotBlocks", "ebs:GetSnapshotBlock"],

    ["ec2:CreateSnapshot"],
    ["ec2:RunInstances"],
    ["iam:AddRoleToInstanceProfile"],
    ["ec2:AssociateIamInstanceProfile", "ec2:DisassociateIamInstanceProfile"],
    ["ec2:ReplaceIamInstanceProfileAssociation"],
    ["autoscaling:CreateLaunchConfiguration", "autoscaling:CreateAutoScalingGroup"],
    ["ec2:DescribeLaunchTemplates", "ec2:DescribeLaunchTemplateVersions"],
    ["ec2:DescribeInstances", "ec2:RunInstances", "ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:CreateTrafficMirrorTarget", "ec2:CreateTrafficMirrorSession", "ec2:CreateTrafficMirrorFilter", "ec2:CreateTrafficMirrorFilterRule"],

    ["ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],

    ["ecs:RunTask"],
    ["ecs:StartTask"],
    ["ecs:UpdateService"],
    ["ecs:CreateService"],
    ["ecs:UpdateServicePrimaryTaskSet"],

    ["elasticfilesystem:ClientMount"],
    ["elasticfilesystem:ClientRootAccess"],
    ["elasticfilesystem:ClientWrite"],
    ["elasticfilesystem:CreateMountTarget"],
    ["elasticfilesystem:ModifyMountTargetSecurityGroups"],
    ["elasticfilesystem:CreateAccessPoint"],

    ["elasticbeanstalk:RebuildEnvironment"],
    ["elasticbeanstalk:CreateApplication", "elasticbeanstalk:CreateEnvironment", "elasticbeanstalk:CreateApplicationVersion", "elasticbeanstalk:UpdateEnvironment"],
    ["elasticbeanstalk:CreateApplicationVersion", "elasticbeanstalk:UpdateEnvironment", "cloudformation:GetTemplate", "cloudformation:DescribeStackResources", "cloudformation:DescribeStackResource", "autoscaling:DescribeAutoScalingGroups", "autoscaling:SuspendProcesses", "autoscaling:SuspendProcesses"],

    ["elasticmapreduce:RunJobFlow"],
    
    ["scheduler:CreateSchedule", "scheduler:UpdateSchedule"],

    ["glue:CreateDevEndpoint"],
    ["glue:CreateJob"],
    ["glue:StartJobRun"],
    ["glue:CreateTrigger"],

    ["kms:CreateKey", "kms:ReplicateKey"],
    ["kms:Decrypt"],

    ["lambda:CreateFunction"],
    ["lambda:InvokeFunction"],
    ["lambda:InvokeFunctionUrl"],
    ["lambda:CreateEventSourceMapping"],

    ["rds:AddRoleToDBCluster"],
    ["rds:CreateDBInstance"],
    ["rds:AddRoleToDBInstance"],
    ["rds:RestoreDBInstanceFromDBSnapshot"],
    ["rds:DownloadDBLogFilePortion"],
    ["rds:StartExportTask"],

    ["redshift:ModifyCluster"],

    ["sns:Publish"],
    ["sns:Subscribe"],
    ["sns:Unsubscribe"],
    
    ["sqs:SendMessage"],
    ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility"],
    ["sqs:PurgeQueue"],

    ["sso:DetachManagedPolicyFromPermissionSet"],
    ["sso:DetachCustomerManagedPolicyReferenceFromPermissionSet"],
    ["sso:DeleteInlinePolicyFromPermissionSet"],
    ["sso:DeletePermissionsBoundaryFromPermissionSet"],

    ["s3:PutBucketNotification"],
    ["s3:PutObject"],
    ["s3:GetObject"],

    ["sagemaker:CreateNotebookInstance"],
    ["sagemaker:CreateProcessingJob"],
    ["sagemaker:CreateTrainingJob"],
    ["sagemaker:CreateHyperParameterTuningJob"],

    ["ses:SendEmail"],
    ["ses:SendRawEmail"],
    ["ses:SendTemplatedEmail"],
    ["ses:SendBulkTemplatedEmail"],
    ["ses:SendBulkEmail"],
    ["ses:SendBounce"],
    ["ses:SendCustomVerificationEmail"],

    ["ssm:GetParameter"],
    ["ssm:GetParameters"],
    ["ssm:ListCommands"],
    ["ssm:GetCommandInvocation"],

    ["states:TestState"],
    ["states:CreateStateMachine"],
    ["states:RevealSecrets"],

    ["workdocs:CreateUser"],
    ["workdocs:GetDocument"],
    ["workdocs:AddResourcePermissions"],
    ["workdocs:AddUserToGroup"],

    ["dlm:CreateLifecyclePolicy"]
]


# Live-tested, non-mutating attack paths and their service-specific HackTricks
# evidence. Keep this deliberately narrow: documentation-only candidates do
# not belong here.
tested_risk_documentation = {
    "lambda:GetFunction": "aws-privilege-escalation/aws-lambda-privesc/README.md",
    "route53domains:GetDomainDetail": "aws-privilege-escalation/aws-route53-domains-privesc/README.md",
    "sts:GetFederationToken": "aws-privilege-escalation/aws-sts-privesc/README.md",
}


live_validated_disclosure_documentation = {
    "account:GetContactInformation": "aws-services/aws-account-management-enum.md",
    "amplify:GetApp": "aws-privilege-escalation/aws-amplify-privesc/README.md",
    "amplify:GetJob": "aws-privilege-escalation/aws-amplify-privesc/README.md",
    "apigateway:GET": "aws-services/aws-api-gateway-enum.md",
    "cloudfront:GetDistribution": "aws-services/aws-cloudfront-enum.md",
    "cloudfront:GetDistributionConfig": "aws-services/aws-cloudfront-enum.md",
    "cloudfront:GetFunction": "aws-services/aws-cloudfront-enum.md",
    "cloudfront:ListDistributions": "aws-services/aws-cloudfront-enum.md",
    "cloudtrail:LookupEvents": "aws-services/aws-security-and-detection-services/aws-cloudtrail-enum.md",
    "ce:GetCostAndUsage": "aws-services/aws-security-and-detection-services/aws-cost-explorer-enum.md",
    "codebuild:BatchGetBuilds": "aws-privilege-escalation/aws-codebuild-privesc/README.md",
    "codebuild:BatchGetProjects": "aws-privilege-escalation/aws-codebuild-privesc/README.md",
    "codecommit:GetBlob": "aws-services/aws-datapipeline-codepipeline-codebuild-and-codecommit.md",
    "codecommit:GetCommit": "aws-services/aws-datapipeline-codepipeline-codebuild-and-codecommit.md",
    "codecommit:GetFile": "aws-services/aws-datapipeline-codepipeline-codebuild-and-codecommit.md",
    "codecommit:GitPull": "aws-services/aws-datapipeline-codepipeline-codebuild-and-codecommit.md",
    "cognito-idp:AdminGetUser": "aws-services/aws-cognito-enum/cognito-user-pools.md",
    "cognito-idp:DescribeIdentityProvider": "aws-services/aws-cognito-enum/cognito-user-pools.md",
    "cognito-idp:ListUsers": "aws-services/aws-cognito-enum/cognito-user-pools.md",
    "cognito-idp:ListUsersInGroup": "aws-services/aws-cognito-enum/cognito-user-pools.md",
    "dynamodb:BatchGetItem": "aws-post-exploitation/aws-dynamodb-post-exploitation/README.md",
    "dynamodb:GetItem": "aws-post-exploitation/aws-dynamodb-post-exploitation/README.md",
    "dynamodb:Query": "aws-post-exploitation/aws-dynamodb-post-exploitation/README.md",
    "dynamodb:Scan": "aws-post-exploitation/aws-dynamodb-post-exploitation/README.md",
    "dynamodb:TransactGetItems": "aws-post-exploitation/aws-dynamodb-post-exploitation/README.md",
    "ec2:DescribeLaunchTemplateVersions": "aws-privilege-escalation/aws-ec2-privesc/README.md",
    "ecr:GetDownloadUrlForLayer": "aws-post-exploitation/aws-ecr-post-exploitation/README.md",
    "ecs:DescribeTaskDefinition": "aws-services/aws-ecs-enum.md",
    "lambda:GetFunctionConfiguration": "aws-privilege-escalation/aws-lambda-privesc/README.md",
    "lambda:GetLayerVersion": "aws-privilege-escalation/aws-lambda-privesc/README.md",
    "logs:FilterLogEvents": "aws-services/aws-security-and-detection-services/aws-cloudwatch-enum.md",
    "logs:GetLogEvents": "aws-services/aws-security-and-detection-services/aws-cloudwatch-enum.md",
    "invoicing:BatchGetInvoiceProfile": "aws-services/aws-invoicing-enum.md",
    "invoicing:GetInvoicePDF": "aws-services/aws-invoicing-enum.md",
    "invoicing:ListInvoiceSummaries": "aws-services/aws-invoicing-enum.md",
    "sagemaker:DescribeTrainingJob": "aws-services/aws-sagemaker-enum/README.md",
    "ses:GetSuppressedDestination": "aws-services/aws-ses-enum.md",
    "ses:ListSuppressedDestinations": "aws-services/aws-ses-enum.md",
    "sns:ListSubscriptions": "aws-services/aws-sns-enum.md",
    "sns:ListSubscriptionsByTopic": "aws-services/aws-sns-enum.md",
    "ssm:GetParameterHistory": "aws-privilege-escalation/aws-ssm-privesc/README.md",
    "tax:GetTaxRegistration": "aws-services/aws-tax-settings-enum.md",
    "tax:ListTaxRegistrations": "aws-services/aws-tax-settings-enum.md",
}
