# VPC ID used for builds
BUILD_VPC_ID ?=

# VPC subnet used for builds
BUILD_SUBNET_ID ?=

# Override for AMI name if needed
BUILD_AMI_NAME ?=

# Default build region
AWS_REGION ?= us-west-2

# Teleport version
TELEPORT_VERSION ?= 4.0.0

# Teleport UID is the UID of a non-privileged 'teleport' user
TELEPORT_UID ?= 1007

# Instance type is a single value, sorry
INSTANCE_TYPE ?= t2.micro

# Use comma-separated values without spaces for multiple regions
# For now, limit AMI to regions with DynamoDB encryption at rest enabled
# https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html
DESTINATION_REGIONS ?= us-west-2,us-east-1,us-east-2,eu-west-1

# Cloudformation stack name to create, e.g. test1
STACK ?=

# Stack parameters, e.g ParameterKey=KeyName,ParameterValue=KeyName ParameterKey=DomainName,ParameterValue=teleport.example.com ParameterKey=DomainAdminEmail,ParameterValue=admin@example.com ParameterKey=HostedZoneID,ParameterValue=AWSZONEID
STACK_PARAMS ?=

# License S3 URI for enterprise builds, e.g. s3://example.com/path/to/license
TELEPORT_LICENSE_URI ?=


# YAML filename
CF_YAML_FILENAME ?= ./oss_acm.yaml

# S3 Bucket ID
S3_BUCKET_ID ?=
export


.PHONY: validate-template
validate-template:
	aws cloudformation validate-template --template-body file://$(CF_YAML_FILENAME)


# Stack functionality
# Create
.PHONY: create-stack
create-stack:
	$(MAKE) validate-template
	aws --region=$(AWS_REGION) cloudformation create-stack --capabilities CAPABILITY_IAM --stack-name $(STACK) --template-body file://$(CF_YAML_FILENAME) --parameters $(STACK_PARAMS)

.PHONY: create-stack-vpc
create-stack-vpc: CF_YAML_FILENAME=./vpc.yaml
create-stack-vpc:
	$(MAKE) create-stack


# Update
.PHONY: update-stack
update-stack:
	$(MAKE) validate-template
	aws --region=$(AWS_REGION) cloudformation update-stack --capabilities CAPABILITY_IAM --stack-name $(STACK) --template-body file://$(CF_YAML_FILENAME) --parameters $(STACK_PARAMS)

.PHONY: update-stack-vpc
update-stack-vpc: CF_YAML_FILENAME=./vpc.yaml
update-stack-vpc:
	$(MAKE) update-stack


# Describe
.PHONY: describe-stack
describe-stack:
	@aws --region=$(AWS_REGION) cloudformation describe-stacks --stack-name $(STACK)

.PHONY: describe-stack-outputs
describe-stack-outputs:
	@aws --region=$(AWS_REGION) cloudformation describe-stacks --stack-name $(STACK) --query 'Stacks[].Outputs[]'

.PHONY: describe-stack-outputs-vpc
describe-stack-outputs-vpc: JENKINS_TEST_STACK_NAME=jenkins-teleport-quickstart-test-stack-vpc
describe-stack-outputs-vpc:
	@aws --region=$(AWS_REGION) cloudformation describe-stacks --stack-name $(STACK) --query 'Stacks[].Outputs[]'


# Delete
.PHONY: delete-stack
delete-stack:
	aws --region=$(AWS_REGION) cloudformation delete-stack --stack-name $(STACK)


.PHONY: check-ent-vars
check-ent-vars:
	@if [ -z "$(TELEPORT_VERSION)" ]; then \
	  echo "TELEPORT_VERSION is not set"; exit 1; \
	fi;

.PHONY: copy-license-from-s3
copy-license-from-s3:
	@if [ ! -z "$(TELEPORT_LICENSE_URI)" ]; then \
	  aws s3 cp $(TELEPORT_LICENSE_URI) files/system/license.pem; \
	fi;
