## Usage

* Install [Terraform](https://learn.hashicorp.com/tutorials/terraform/install-cli)
* Run `AWS_PROFILE="<profile_name>" terraform init` or `TF_VAR_profile="<profile> terraform init` 

This initialises the backend and downloads the state from the relevant S3 bucket, which has been preconfigured in the account for simplicity.

### Accessing the instances

Recently, the architecture has been simplified to remove the need to provision a bastion host. A bastion host requires assigning an SSH key pair to each instance, ensuring that the keys relevant public keys are distributed across the instances so that a user can access it when passing their private key as part of the secure authentication process. However, by using Session Manager, we eliminate the need to use SSH at all - providing even greater security for the instances and simplified management access.

To do this, each instance which starts up has the relevant role attached to it and SSM agent installed, granting the AWS service access to the instance, allowing you to attach to it using Session Manager. The easiest way to do this is through the [AWS Management Console](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-sessions-start.html#start-ec2-console).