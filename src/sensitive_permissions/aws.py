

very_sensitive_combinations = [
    ["iam:PassRole"],

    ["codebuild:StartBuild", "codebuild:StartBuildBatch"],

    ["cognito-identity:update-identity-pool"],
    ["cognito-idp:AdminAddUserToGroup"],
    ["cognito-idp:AdminConfirmSignUp"],
    ["cognito-idp:AdminCreateUser"],
    ["cognito-idp:AdminSetUserPassword"],
    ["cognito-idp:AdminSetUserSettings"],
    ["cognito-idp:SetUserMFAPreference"],
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

    ["msk:UpdateSecurity"],

    ["rds:ModifyDBInstance"],

    ["redshift:DescribeClusters", "redshift:GetClusterCredentials"],

    ["redshift:DescribeClusters", "redshift:GetClusterCredentialsWithIAM"],

    ["route53:CreateHostedZone", "route53:ChangeResourceRecordSets", "acm-pca:IssueCertificate",  "acm-pca:GetCertificate"]

    ["sns:AddPermission"],

    ["sqs:AddPermission"],

    ["identitystore:CreateGroupMembership"],
    ["sso:PutInlinePolicyToPermissionSet", "sso:ProvisionPermissionSet"],
    ["sso:AttachManagedPolicyToPermissionSet", "sso:ProvisionPermissionSet"],
    ["sso:AttachCustomerManagedPolicyReferenceToPermissionSet", "sso:ProvisionPermissionSet"],
    ["sso:CreateAccountAssignment"],
    ["sso:GetRoleCredentials"],

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
    ["sts:GetFederationToken"],
    ["sts:AssumeRoleWithSAML"],
    ["sts:AssumeRoleWithWebIdentity"]
]

sensitive_combinations = [
    ["apigateway:POST"],
    ["apigateway:GET"],
    ["apigateway:UpdateRestApiPolicy", "apigateway:PATCH"],
    ["apigateway:PutIntegration"],
    ["apigateway:CreateDeployment"],
    ["apigateway:UpdateAuthorizer"],
    ["apigateway:UpdateVpcLink"],
    ["apigateway:UpdateGatewayResponse"],
    ["apigateway:UpdateStage"],
    ["apigateway:PutMethodResponse"],
    ["apigateway:UpdateRestApi"],
    ["apigateway:CreateApiKey"],
    ["apigateway:UpdateApiKey"]

    ["chime:CreateApiKey"],

    ["codebuild:CreateProject"],
    ["codebuild:UpdateProject"],

    ["s3:GetObject"],
    ["s3:PutObject"],

    ["codepipeline:CreatePipeline", "codebuild:CreateProject", "codepipeline:StartPipelineExecution"],
    ["codepipeline:pollforjobs"],

    ["codestar:CreateProject"],
    ["codestar:CreateProjectFromTemplate"],

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
    ["ec2:describe-launch-templates", "ec2:describe-launch-template-versions"],
    ["ec2:DescribeInstances", "ec2:RunInstances", "ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:CreateTrafficMirrorTarget", "ec2:CreateTrafficMirrorSession", "ec2:CreateTrafficMirrorFilter", "ec2:CreateTrafficMirrorFilterRule"],

    ["ecr:GetAuthorizationToken", "ecr:BatchGetImage"],

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
    ["sns:Unsubscribe"]
    
    ["sqs:SendMessage"],
    ["sqs:SendMessageBatch"]
    ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility"],
    ["sqs:PurgeQueue"]

    ["sso:DetachManagedPolicyFromPermissionSet"],
    ["sso:DetachCustomerManagedPolicyReferenceFromPermissionSet"],
    ["sso:DeleteInlinePolicyFromPermissionSet"],
    ["sso:DeletePermissionBoundaryFromPermissionSet"],

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

    ["DLM:CreateLifeCyclePolicy"]
]