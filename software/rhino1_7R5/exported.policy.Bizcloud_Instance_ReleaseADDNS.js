
/**********************

dt671147.tenant01.hcs.cscehub.com


https://technet.microsoft.com/en-us/library/hh849798.aspx

-WorkgroupName<String>
-Options<JoinOptions>

*********************

client = new minion.remote.Client({publicKey: "agil_svc", privateKey: 'M3sh@dmin\!', type:"winrm", host: "10.92.2.254"});client.open();

var removeScript = "$username = \"agil_svc\"; $password = \"M3sh@dmin\!\"; $cred = New-Object System.Management.Automation.PSCredential($username,$password);Add-Computer -ComputeName \"bwalsh21\" -DomainName \"tenant01.hcs.cscehub.com\" -Credential $cred -Force";

var res = client.exec("powershell", removeScript); res.stdout;res.exitcode;

*********************

var res = "$username = \"agil_svc\"; $password = \"M3sh@dmin\!\"; $cred = New-Object System.Management.Automation.PSCredential($username,$password);Get-ADComputer -ComputeName \"dt671147\" -Credential $cred | Ft DistinguishedName -HideTableHeaders;";

var res = "$username = \"agil_svc\"; $password = \"M3sh@dmin\!\"; $cred = New-Object System.Management.Automation.PSCredential($username,$password);Get-ADComputer dt671147  | Ft DistinguishedName -HideTableHeaders;$r = $cred.UserName; Write-Host $r;"; 
var res1 = client.exec("powershell", res); res1.stdout;

var res = "$cred = New-Object System.Management.Automation.PSCredential(\"ag\",\"M3\"); Write-Host $r;"; 
var res1 = client.exec("powershell", res); res1.stdout;

var res1 = client.exec("powershell", "set-variable -name desc -value \"A descriptio\"; get-variable -name desc;"); res1.stdout;res1.exitcode;

*********************

res = client.exec("powershell", "Get-ADComputer bwalsh21 | Ft DistinguishedName -HideTableHeaders");

res = client.exec("powershell", "Get-ADComputer dt671147 | Ft DistinguishedName -HideTableHeaders");

var res = "$username = ConvertTo-SecureString username -AsPlainText -Force; Write-Host $username.ToString();";
var res1 = client.exec("powershell", res);


var res = "$username = \"agil_svc\"; $password = \"M3sh@dmin\!\"; $password = ConvertTo-SecureString -string $password;Write-Host $password";
var res1 = client.exec("powershell", res);res1.stdout;

var res = "try { $username = \"agil_svc\"; $password = \"M3sh@dmin\!\"; $password = ConvertTo-SecureString -string $password; $cred = New-Object System.Management.Automation.PSCredential($username,$password);Write-Host \"NOW\";} catch { Write-Host $_.Exception.Message }";

var res = "try { $username = \"agil_svc\"; $password = \"M3sh@dmin\!\"; $true_password = $password | ConvertTo-SecureString -AsPlainText -Force; Write-Host \"NOW\";} catch { Write-Host $_.Exception.Message }";

var res = "try { $username = \"agil_svc\"; $password = \"M3sh@dmin\!\"; $true_password = $password | ConvertTo-SecureString -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential($username,$true_password); Write-Host \"NOW\";} catch { Write-Host $_.Exception.Message }";

var res = "try { $username = \"agil_svc\"; $password = \"M3sh@dmin\!\"; $true_password = $password | ConvertTo-SecureString -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential($username,$true_password); Get-ADComputer dt671147 -Credential $cred | Ft DistinguishedName -HideTableHeaders; } catch { Write-Host $_.Exception.Message }";



var res1 = client.exec("powershell", res);

*********************/



/**
* @Type Policy
* @Name Bizcloud:Instance:ReleaseADDNS
* @Description Remove AD/DNS entries on release of instances (NOT on stop)
* @PolicyType LifecycleValidation
* @PolicyAssetType instance
* @PolicyLifecycleEvent Release
*/
!this.minion ? importScript('Bizcloud:Utility:Library') : minion;

var logger = minion.logger.getLogger('Bizcloud:Instance:ReleaseADDNS');
var instance = minion.asset;

function getVariableValue(myvar)
{
	if (myvar) {
		return myvar.value;		
	}
}

logger.info('Begin releasing instance: {}', instance);

/*
	Remove the AD/DNS entries for a passed in instance.  
	The instance can be a Linux box and a Windows box.
	
	We do not need the template nor do we need the packageList as we are not
	applying a package (running anything on/to) the guest VM 
	that Agility is managing.

	This occur irrespective of the state that the VM is in (stopped or running).

	We asssume that the active directory instance is hosting DNS (ADDNS)
	Therefore we do NOT use the cloud variables 

	BIZ_DNS_DOMAIN, BIZ_DNS_SERVER 	
	(we just use the AD variables as we only connect to AD, including for DNS)

	This script should be extend in the future to use a different DNS than AD
	if configured.  It should also support ADDNS and bind.

	Finally this script always returns true (as per the script it replaces). 
	This means the instance is always released.
*/
var stackOS = instance.stack.operatingSystem;
var stackBaseOS = stackOS.split('\\|')[0];
var stackBaseOSL = stackBaseOS.toLowerCase();


var client = null

try {

	//get need to get the configuration variables from the cloud provider
	//these variables are used to access the active directory domain controller
	var cloud_vars = instance.cloud.variables;
        var ad_server_ip = getVariableValue(my_cloud_vars["BIZ_AD_SERVER"]);
        var ad_user = getVariableValue(my_cloud_vars["BIZ_SVC_ACCOUNT"]);
        var encrypted_password = getVariableValue(my_cloud_vars["BIZ_SVC_PWD"]);
        var domain_name = getVariableValue(my_cloud_vars["BIZ_AD_DOMAIN"]);

	if (!ad_server_ip || !ad_user || !domain_name) {

		logger.error("active directory server {} active directory user id {} and domain_name {} all need to be set to do a release of an instance",
				ad_server_ip, ad_user, domain_name);
		true;
	}
	
	var unencrypted_password = minion.$(instance.cloud.ICloud.decryptVariable(instance.cloud.id, encrypted_password.id, null));

	client= new minion.remote.Client({publicKey: ad_user, privateKey: unencrypted_password, type:"winrm", host: ad_server_ip});
	client.open();

       	var psResponse = null;

	var computerHostName = instance.hostname;

	try {
		//Remove the DNS record for host
		psResponse = client.exec("powershell",
                        "remove-dnsserverresourcerecord -ZoneName \"" + domain_name + "\" -RRType \"A\" -Name \"" + computerHostName + "\" -Force");
		if (psResponse.exitCode != 0) {
			logger.error("there was an error removing the domain {} host name record for host {}, the error code is {}",
				domain_name, computeHostName);
		}
	}
	catch(e1) {
		logger.error("exception {} occurred during remove of dns record for computer {}", e1, computeHostName);
	}

	try {
		//get the machine's distinguished name
		psResponse = client.exec("powershell", "Get-ADComputer " + computerHostName + " | Ft DistinguishedName -HideTableHeaders");
		if (psResponse.exitCode == 0) {

			//set the distinguished name in dn variable
			var fqdn = res.stdout.trim();
		
			//This string becomes a try catch block to remove the instance from the domain	
			//The Remove-Computer command is documented at https://technet.microsoft.com/en-us/library/hh849816.aspx
			var removeScript = "try {";
			removeScript += "$username =" + ad_user + ";";
			removeScript += "$password =" + unencrypted_password + ";";
			removeScript += "$true_password = $password | ConvertTo-SecureString -AsPlainText -Force;";
			removeScript += "$cred = New-Object System.Management.Automation.PSCredential($username,$true_password);";
			removeScript += "Remove-Computer -UnjoinDomainCredential $cred -ComputerName " + fqdn + " -Force"; 
			removeScript += "  } catch { Write-Host $_.Exception.Message } ";
			
			removeScript += "$cred = New-Object System.Management.Automation.PSCredential($username,$password);";
			psResponse = client.exec("powershell", removeScript);
			if (psResponse.exitCode == 0) {
				logger.error("error on call to remove instance with hostname {} from active directory, exitcode {}", 
					computeHostName, psResponse.exitCode);
			}
			else {
				logger.info("The host with name {} was removed from the Active directory domain {}", computerHostName, domain_name);
			}
		}
		else {
			logger.error("error on call to get instance with hostname {} active directory information, exitcode {}", 
				computeHostName, psResponse.exitCode);
		}
	}
	catch(e2) {
		logger.error("exception {} occurred during remove of active directory domain record for computer {}", e2, computeHostName);
	}
} 
catch(e) {
	logger.warn('An error occurred during the ADDNS release: {}', e, minion.util.getException(e));
} 
finally {
	if (client && client.isOpen()) {
		client.close();
        }
}
true;
