
importScript("Bizcloud:NSX:Functions")

//KATHY-TEST
var httpClient = new minion.http.HttpClient({username: 'admin', password: 'vmwareNextGEN1\!'});
createFullVirtualServerFromAgilityAssetSimple(httpClient, '20.176.209.251' , 'edge-408', asset);

function addAddressBackToPool2(httpClient, NSXManagerIp, ipPoolId,ipAddress)
{
        minion.logger.info('trying to add ip address {} back to the pool {}', ipAddress, ipPoolId);

        //add the address back to the ippool from which it came (deallocate)
        var deallocateCallStr = "https://" + NSXManagerIp 
                        + "/api/2.0/services/ipam/pools/" + ipPoolId + "/ipaddresses/"  + ipAddress;

        var deallocateRequest = {};
        deallocateRequest.headers = {"Content-Type":"application/xml"};
        deallocateRequest.body = {};
        var deallocateResponse = httpClient.httpDelete(deallocateCallStr, deallocateRequest);

        if (deallocateResponse.code > 300) {
                minion.logger.error("could not add ip address {} back to pool {}", ipAddress, ipPoolId);
                return false;
        }
        else {
                minion.logger.error("successfully added ip address {} back to pool {}", ipAddress, ipPoolId);
                return true;
        }
}

function allocateIpAddressFromPool2(httpClient, NSXManagerIp, ipPoolId)
{
        var allocateRequest = {};
        allocateRequest.headers = {"Content-Type":"application/xml"};
        allocateRequest.body = "<ipAddressRequest><allocationMode>ALLOCATE</allocationMode></ipAddressRequest>";
        var allocateResponse = httpClient.httpPost("https://" + NSXManagerIp + "/api/2.0/services/ipam/pools/" + ipPoolId + "/ipaddresses", allocateRequest);

        if (allocateResponse.code > 300) {

                minion.logger.error("could not allocate ip address from the ip pool {}" + ipPoolId);
                return null;
        }
        else {
                var ipAddress = findStrWithXmlPath(allocateResponse.data, "//allocatedIpAddress/ipAddress/text()");
                if (ipAddress) {
                        minion.logger.info("allocated ip address {}", ipAddress);
                        return ipAddress;
                }
                else {
			//was -1
                        return null;
                }
        }
}

function getSecondaryPoolIdFromName(edgeId)
{
	return "BURT";
}

/***** GET OBJECT ID BY NAME *******/
function getApplicationProfileIdByName(httpClient, NSXManagerIp, edgeId, applicationProfileName)
{
	var res = commonGet("https://" + NSXManagerIp + "/api/4.0/edges/" + edgeId + "/loadbalancer/config/applicationprofiles");
	if (successfulRestCall(res)) {
		var applicationProfileId = minion.xml.applyXPath(res.data, 
			'//loadbalancer/applicationProfile/name/text()[.="' + applicationProfileName + '"]../../applicationProfileId/text()');
		return applicationProfileId;
	}
	else {
		return null;
	}
}

function getMonitorIdByName(httpClient, NSXManagerIp, edgeId, monitorName)
{
	var res = commonGet("https://" + NSXManagerIp + "/api/4.0/edges/" + edgeId + "/loadbalancer/config/monitors");
	if (successfulRestCall(res)) {
		var monitorId = minion.xml.applyXPath(res.data, 
			'//loadbalancer/monitor/name/text()[.="' + monitorName + '"]../../monitorId/text()');
		return monitorId;
	}
	else {
		return null;
	}
}

/**** CREATE OBJECT METHODS ****/

function createApplicationProfile(httpClient, NSXManagerIp, applicationProfileName)
{
	//WERK
	//support https as well start with http
	//var xml = buildApplicationProfileXml(applicationProfileName, true, true, 'http', 'JSESSIONID', 'insert');
	var xml = buildDefautApplicationProfileHttpXml(applicationProfileName);

	var res = commonPost("https://" + NSXManagerIp + "/api/4.0/edges/" + edgeId + "/loadbalancer/config/applicationprofiles");
	if (successfulRestCall(res)) {
		return true;
	}
	return false;
}

function createPool(httpClient, NSXManagerIp, poolName, transparent, algorithm, monitorId)
{
	var xml = buildPoolXml(poolName, transparent, algorithm, monitorId);
	var res = commonPost("https://" + NSXManagerIp + "/api/4.0/edges/" + edgeId + "/loadbalancer/config/pools", xml);
	if (successfulRestCall(res)) {
		return getPoolIdByName(httpClient, NSXManager, poolName);
	}
	else {
		minion.logger.error("member ip pool {} could not be created for edge {}", poolName, edgeId);
		return null;
	}
}

function createVirtualServerReturnId(httpClient, NSXManagerIp, edgeId, virtualServerName, vip, protocol, port, poolId, applicationProfileId)
{
	var xml = buildVirtualServerXmlSimple(virtualServerName, vip, protocol, port, poolId, applicationProfileId);
	minion.logger.info('trying to create virtual server for edge {} with xml {}', edgeId, xml);
	var res = commonPost("https://" + NSXManagerIp + "/api/4.0/edges/" + edgeId + "/loadbalancer/config/virtualservers", xml);
	if (successfulRestCall(res)) {
		var virtualServerId = getVirtualServerIdByName(httpClient, NSXManager, edgeId, virtualServerName);
		minion.logger.info('virtual server created successfully with id {}', virtualServerId);
		return virtualServerId;
	}
	else {
		minion.logger.error("virtual server {} could not be created for edge {}", virtualServerName, edgeId);
		return null;
	}

}

/*
	(asset should start as a template)

	* use default http monitor
	* create pool with no members
	* use default application profile
	* no application rules

	* associate pool-id with template (later also a container)

	//The asset will have the following values
	//secondaryIp from pool (pool name from edge)
	//protocol
	//port
	//create a pool store the name in the template	
	//use the default profile
*/

//Assuming http need to make this a function of protocol and take in a port
function createFullVirtualServerFromAgilityAssetSimple(httpClient, NSXManagerIp, edgeId, asset)
{
	//ensure load balancer on the edge is enabled
	if (enableLoadBalancer(httpClient, NSXManagerIp, edgeId)) {

		//WERK the default should be by type (http, https, tcp)
		var applicationProfileId = getDefaultApplicationProfileCreateIfNeeded(httpClient, NSXManagerIp, edgeId);
		if (applicationProfileId) {

			var monitorId = getDefaultMonitorCreateIfNeeded(httpClient, NSXManagerIp, edgeId);
			if (monitorId) {

				//create the pool for the virtual server (starting with http)
				var poolId = createPool(httpClient, NSXManagerIp, poolName = asset.name, transparent = false, algorithm = 'round-robin', monitorId);
				if (poolId) {

					//store the poolId in the passed in asset which is normally a template
					asset.setAssetProperty("poolId", "" + poolId, true);
	
					//get an Ip address from the secondary pool associated with the edge
					//if this fails we should delete the pool	
					var secondaryPoolId = getSecondaryPoolId(edgeId);
					if (secondaryPoolId) {

						//perhaps this should be higher as if an address is not available we should fail quickly
						var allocatedAddress = allocateIpAddressFromPool2(httpClient, NSXManagerIp, secondaryIpPoolId);
						if (allocatedAddress) {
						   var virtualServerId = 
							createVirtualServerReturnId(httpClient, NSXManagerIp, edgeId, 
								virtualServerName = asset.name, vip = allocatedIpAddress,
								protocol = 'http', port = 80, poolId, applicationProfileId);
						   return virtualServerId;
						}
					}
				}
			}
		}
	}
	else {
		minion.logger.error('could not create full virtual server for load balancer in edge {}', edgeId);
		return null;
	}
	return null;
}


/************ DEFAULT OBJECTS **************/ 
//type can be http, https, tcp -- really should create one per type
function getDefaultApplicationProfileCreateIfNeeded(httpClient, NSXManagerIp, edgeId)
{
	//get application profile by name first if this fails build it	
	var applicationProfileId = getApplicationProfileIdByName(httpClient, NSXManagerIp, edgeId, 'default');

	if (!applicationProfileId) {

		//WERK
		//should have a createDefaultApplicationProfileByType	
 		createApplicationProfile(httpClient, NSXManagerIp, 'default');
		return getApplicationProfileIdByName(httpClient, NSXManagerIp, edgeId, 'default');
	}
	else {
		return applicationProfileId;
	}
}

//should have one per type
function getDefaultMonitorCreateIfNeeded(httpClient, NSXManagerIp, edgeId)
{
	//get application profile by name first if this fails build it	
	var monitorId = getMonitorIdByName(httpClient, NSXManagerIp, edgeId, 'default');
	if (!monitorId) {

 		createApplicationProfile(httpClient, NSXManagerIp, 'default');
		return getMonitorIdByName(httpClient, NSXManagerIp, edgeId, 'default');
	}
	else {
		return monitorId;
	}
}

/**** FUNCTIONS FOR VIRTUAL SERVERS ******/
function getVirtualServerIdByName(httpClient, NSXManager, virtualServerName)
{
	var res = commonGet(httpClient, "https://" + NSXManager + "/api/4.0/edges/" + edgeId + "/loadbalancer/config/virtualservers");
	if (!successfulRestCall(res)) {
		var poolId = minion.xml.applyXPath(config, '//loadBalancer/virtualServer/name/text()[.="' + virtualServerName + '"]../../virtualServerId/text()');
	}
	return null;
}

/**** FUNCTIONS FOR WORKING WITH AGILITY POOLS AND MEMBERS OF POOLS **********/
function getPoolIdByName(httpClient, NSXManager, poolName)
{
	var res = commonGet(httpClient, "https://" + NSXManager + "/api/4.0/edges/" + edgeId + "/loadbalancer/config/pools/");
	if (!successfulRestCall(res)) {
		var poolId = minion.xml.applyXPath(config, '//pool/name/text()[.="' + poolName + '"]../../poolId/text()');
	}
	return null;
}

function getPoolXmlFromAgilityAsset(httpClient, NSXManager, edgeId, asset)
{
	//check for null and type
	var poolId = getValueFromAssetProperty(asset.findAssetProperty("poolId"));

	if (poolId) {
		var res = getPoolXmlFromPoolId(httpClient, edgeId, poolId);
		if (successfulRestCall(res)) {
			return res.data;	
		}
		else {
			minion.logger.error('could not query for poolId {} from edge {}', poolId, edgeId);
			return null;
		}
	}
	minion.logger.error('could not find pool-id in asset so we could not get xml for pool');
	return null;
}

function getPoolXmlFromPoolId(httpClient, edgeId, poolId)
{
	var res = commonGet(httpClient, "https://" + config.nsxmanagerip + "/api/4.0/edges/" + edgeId + "/loadbalancer/config/pools/" + poolId);
	if (!successfulRestCall(res)) {
		return null;
	}
	return res;
}

/***** (POOL) MEMBER FUNCTIONS ******/
function appendMemberToPoolAssociatedWithAgilityAsset(httpClient, NSXManagerIp, edgeId, asset, memberXml)
{
	var poolXml = getPoolXmlFromAgilityAsset(httpClient, edgeId, asset);

	var newPoolDefinitionWithAppendedMember = p.substring(0,p.indexOf("</pool>")) + memberXml + "</pool>";
	var res = commonPost("https://" + NSXManagerIp + "/api/4.0/edges/edgeId/loadbalancer/config/pools", newPoolDefinitionWithAppendedMember);
	if (!successfulRestCall(res)) {

	}
	return res;
}

function removeMemberFromPoolAssociatedWithAgilityAsset(httpClient, NSXManagerIp, edgeId, asset, memberIpAddress)
{
	//var poolXml = getPoolXmlByName(httpClient, NSXManager, edgeId, poolName);
	var poolXml = getPoolXmlFromAgilityAsset(httpClient, edgeId, asset);

	//find xml before the first <member> tag.  It is assumed that the member tags
	//come at the end of the pool xml
	var pos = p.indexOf("<member>");
	
	//start the new pool definition with the content before the first <member> element
	var newPoolDefinition = p.substring(0,pos);

	//The end tag for a <member> element
	var endMemberStr = "</member>";

	//we pull out each member and search for the memberIpAddress in said members
	//if found we do not include that member element in the new definition of the pool.
	while(pos != -1)
	{
		//position of the next </member> element in the pool definition
        	memberEnd = p.indexOf(endMemberStr, pos) + endMemberStr.length;
		//The actual current member element 
		var memberXml = p.substring(pos,memberEnd);
		//look for the memberIpAddress (ip address of the member to remove) in the
		//current member element
		if (memberXml.indexOf(memberIpAddress) < 0) {
			//if not ip address is not found keep this member
			newPoolDefinition += memberXml;
		}
        	pos = p.indexOf("<member>",memberEnd);
	}
	//since we have added all the members back (except for the one being removed) 
	//append the closing </pool> tag
	newPoolDefinition += "</pool>";

	var res = commonPost("https://" + NSXManagerIp + "/api/4.0/edges/edgeId/loadbalancer/config/pools/" + poolId);
	if (!successfulRestCall(res)) {
		minion.logger.error('failed to remove the member with ip address {} from the load balance pool associated with asset {}'
					, memberIpAddress, asset.name);
		return false;
	}
	return true;
}

/***** LOAD BALANCER FUNCTIONS ********/
function getLoadbalancerConfiguration(httpClient, NSXManagerIp, edgeId)
{
	var res = commonGet("https://" + NSXManagerIp + "/api/4.0/edges/edgeId/loadbalancer/config");
	if (successfulRestCall(res)) {
		return res.data;		
	}
	else {
		return null;
	}
}	

function enableLoadBalancer(httpClient, NSXManagerIp, edgeId)
{
	//get loadbalancer configuration
	var config = getLoadbalancerConfiguration(httpClient, NSXManagerIp, edgeId);
	if (config) {
		var enabled = minion.xml.applyXPath(config, '//loadbalancer/enabled/text()');
		if (enabled == 'true') {
			return;  //nothing to do the load balancer is already enabled
		}

		//build the new load balancer xml with enabled set to true
		var newConfig = config.substring(0,config.indexOf("<enabled>"))
				+ "<enabled>true</enabled>" 
				+ config.substring(p.indexOf("</enabled>") + "</enabled>".length);
		var res = commonPut("https://" + NSXManagerIp + "/api/4.0/edges/edgeId/loadbalancer/config");
		if (!successfulRestCall(res)) {
			minion.logger.error('issue enabling load balancer for edge {} and NSX manager {}', edgeId, NSXManagerIp);	
		}
		return true;
	}
}

/*** BUILD XML PARTS ***/
function buildPoolXml(poolName, transparent, algorithm, monitorId)
{
	var xml = "<pool>" 
			+ "<name>" + poolName + "</name>"
			+ "<description>" + poolName + "</description>"
			+ (transparent ? ("<transparent>" + transparent + "</transparent>") : "")
			//optional defaults to round-robin, other values ip-hash, uri, leastconn
			+ (algorithm ? ("<algorithm>" + algorithm + "</algorithm>") : "")
			+ (monitorId ? ("<monitorId>" + monitorName + "</monitorId>") : "")
			+ "</pool>";

	return xml;
}

function buildMemberXml(memberName, ipAddress, port, name)
{
	var xml = "<member>"
			+ "<memberId>" + memberName + "</memberId>"
			+ "<ipAddress>" + ipAddress + "</ipAddress>"
			+ "<weight>1</weight>"
			+ "<port>" + port + "</port>"
			+ "<minConn>10</minConn>"
			+ "<maxConn>100</maxConn>"
			+ "<name>" + name + "</name>"
			+ "</member>";
	return xml;
}

/**** MONITOR XML FUNCTIONS ******/
function buildTcpMonitorXmlDefault(monitorName)
{
        return buildTcpMonitorXml(monitorName, interval = 3, timeout = 30, maxRetries = 3, protocolMethod = null);
}

function buildTcpMonitorXml(monitorName, interval, timeout, maxRetries, protocolMethod)
{
        return buildMonitorXml(monitorName, monitorType = 'tcp', interval, timeout, maxRetries, protocolMethod
                                ,url = null, expectedValue = null, send = null, receive = null);
}

function buildMonitorXml(monitorName, monitorType, interval, timeout, maxRetries, protocolMethod, url, expectedValue, send, receive)
{
        var xml = "<monitor>"
                        //required is http, https, tcp
                        + "<type>" + monitorType + "</type>"
                        //default is 5
                        + (interval ? ("<interval>" + interval + "</interval>") : "")
                        //default is 15
                        + (timeout ? ("<timeout>" + timeout + "</timeout>") : "")
                        //default is 3
                        + (maxRetries ? ("<maxRetries>" + maxRetries + "</maxRetries>") : "")
                        //is the http method/trace/connect
                        + (protocolMethod ? ("<method>" + protocolMethod + "</method>") : "")
                        //for http and https
                        + (url ? ("<url>" + url + "</url>") : "")
                        + (expectedValue ? ("<expected>" + expectedValue + "</expected>") : "")
                        + (send ? ("<send>" + send + "</send>") : "")
                        + (receive ? ("<receive>" + receive + "</receive>") : "")
                        //required
                        + "<name>" + monitorName + "</name>"
                        + "</monitor>";
        return xml;
}

/*********** VIRTUAL SERVER XML FUNCTIONS ***************/

function buildVirtualServerXmlSimple(virtualServerName, vip, protocol, port, poolId, applicationProfileId) 
{
	return buildVirtualServerXml(virtualServerName, virtualServerName, vip, protocol, port, 
				connectionLimit = null, connectionRateLimit = null, poolId, applicationProfileId, 
				enableServiceInsertion = null, acceleration = null);

}

function buildVirtualServerXml(virtualServerName, description, vip, protocol, port, 
				connectionLimit, connectionRateLimit, poolId, applicationProfileId, 
				enableServiceInsertion, acceleration)
{
	var xml = "<virtualServer>"
			+ "<name>" + virtualServerName + "</name>"
			//optional set to the name
			+ "<description>" + description + "</description>"
			//default is true
			+ "<enabled>true</enabled>"
			//required
			+ "<ipAddress>" + vip + "</ipAddress>"
			//required http, https, tcp
			+ "<protocol>" + protocol + "</protocol>"	
			//required 1-65535
			+ "<port>" + port + "</port>"
			+ (connectionLimit ? ("<connectionLimit>" + connectionLimit + "</connectionLimit>") : "")
			+ (connectionRateLimit ? ("<connectionRateLimit>" + connectionRateLimit + "</connectionRateLimit>") : "")
			//required
			+ "<applicationProfileId>" + applicationProfileId + "</applicationProfileId>"
			//This is optional but we are requiring it 
			+ "<defaultPoolId>" + poolId + "</defaultPoolId>"
			//optional default is false
			+ (enableServiceInsertion ? ("<enableServiceInsertion>" + enableServiceInsertion + "</enableServiceInsertion>") : "")
			//optional default is false	
			+ (acceleration ? ("<accelerationEnabled>" + acceleration + "</accelerationEnabled>") : "")
			+ "</virtualServer>";
	return xml;
}

/****** APPLICATION PROFILE XML ***************/
function buildDefautApplicationProfileHttpXml(applicationProfileName)
{
	return buildApplicationProfileXml(applicationProfileName, true, true, 'http', 'JSESSIONID', 'insert');
}

/*  Implement later getting an object passed in
function buildApplicationProfileHttpXml(applicationProfileName, insertXForwarded, sslPassthrough, method, cookieName, cookieMode)
{
	return buildApplicationProfileXml(applicationProfileName, insertXForwarded, sslPassthrough, method,  cookieName, cookieMode);
}

function buildApplicationProfileHttpsXml()
{
	//cookie method should be 
	//fix later
	return buildApplicationProfileHttp();
}
*/


//This needs to be more complex to support https (CIPHERS etc see docs)
//take in an object in the future
function buildApplicationProfileXml(applicationProfileName, name, insertXForwarded, method, sslPassthrough, cookieName, cookieMode)
{
	var xml = "<applicationProfile>"
			"<name>" + applicationProfileName + "</name>"
			"<insertXForwardedFor>" + insertXForward + "</insertXForwardedFor>"
			"<sslPassthrough>" + sslPassthrough + "</sslPassthrough>"
			"<persistence>"
			"<method>" + method + "</method>"
			"<cookieName>" + cookieName + "</cookieName>"
			//insert/prefix/app
			"<cookieMode>" + cookieMode + "</cookieMode>"
			"</persistence>"
			"</applicationProfile>";
	return xml;
}
