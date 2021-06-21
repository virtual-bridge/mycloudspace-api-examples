# MyCloudSpace API Examples
Examples for using MyCloudSpace via the RESTful api

## Structure
The project will be organised into folders based on the base language. There are examples for you to login with 2fa using the existing credentials you have for the system as well as via api key. If you would like an API key for your user please contact us.

### Powershell

#### ChangePowerAndSpecOfEnvironment.ps1
Designed as a script to power off and de-spec a set of servers to save resource costs when an environment such as Dev/Test is not in use. When required the script can power the machines back on and set the specification of the server (CPU, Memory etc) back to desired values as defined in the script.

#### TakeSnapshotOfVirtualMachine.ps1
Finds a single VM by Hostname (guest hostname) and if found, takes a snapshot with the provided name. Waits for snapshot to become active then terminates. Will exit out if snapshot does not exist on platform withing ~35 seconds.

## Disclaimer

THE INFORMATION CONTAINED IN THE VIRTUAL BRIDGE DEVELOPER DOCUMENTATION AND EXAMPLES IS INTENDED FOR SOFTWARE DEVELOPERS INTERESTED IN DEVELOPING SERVICE MANAGEMENT APPLICATIONS USING THE MYCLOUDSPACE APPLICATION PROGRAMMING INTERFACE (API). THE DOCUMENT IS FOR INFORMATIONAL PURPOSES ONLY AND IS PROVIDED “AS IS.”

Except as set forth in VIRTUAL BRIDGE general terms and conditions, cloud terms of service and/or other agreement you sign with VIRTUAL BRIDGE, VIRTUAL BRIDGE assumes no liability whatsoever, and disclaims any express or implied warranty, relating to its services including, but not limited to, the implied warranty of merchantability, fitness for a particular purpose, and noninfringement.

Although part of the document may explain how VIRTUAL BRIDGE services may work with third party products, the information contained in the document is not designed to work with all scenarios. Any use or changes to third party products and/or configurations should be made at the discretion of your administrators and subject to the applicable terms and conditions of such third party. VIRTUAL BRIDGE does not provide technical support for third party products, other than specified in your hosting services or other agreement you have with VIRTUAL BRIDGE and VIRTUAL BRIDGE accepts no responsibility for third-party products.

VIRTUAL BRIDGE cannot guarantee the accuracy of any information presented after the date of publication.