[comment]: # "Auto-generated SOAR connector documentation"
# Carbon Black ThreatHunter

Publisher: Carbon Black  
Connector Version: 1\.0\.0  
Product Vendor: Carbon Black  
Product Name: ThreatHunter  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.2\.7532  

Integrates Phantom with the Carbon Black PSC environment


<div class="document">

<div class="documentwrapper">

<div class="body" role="main">

<div id="usage-notes" class="section">

# Usage notes <a href="#usage-notes" class="headerlink" title="Permalink to this headline">¶</a>

<div class="toctree-wrapper compound">

</div>

<div id="threat-feed-management" class="section">

## Threat Feed Management <a href="#threat-feed-management" class="headerlink" title="Permalink to this headline">¶</a>

Threat feed actions support the use of the v2 API specification. They require an organization key to
work correctly. A single threat feed is created per Phantom instance. Additional reports should be
created and assigned to the feed by using the Case action within Phantom. Each report will contain
the values for the artifacts in the case. The report id in Carbon Black ThreatHunter is assigned to
the case id. Independent actions can also be taken directly in Phantom using playbooks.

<div id="documentation" class="section">

### Documentation <a href="#documentation" class="headerlink" title="Permalink to this headline">¶</a>

For product information, please refer to
<a href="https://www.carbonblack.com/products/cb-threathunter/" class="reference external">https://www.carbonblack.com/products/cb-threathunter/</a>
. For help with APIs or developer needs, please refer to
<a href="https://developer.carbonblack.com/" class="reference external">https://developer.carbonblack.com/</a>
.

</div>

<div id="support" class="section">

### Support <a href="#support" class="headerlink" title="Permalink to this headline">¶</a>

Please contact Carbon Black Support for any issues relating to this app. Support can be emailed via
<a href="mailto:support%40carbonblack.com" class="reference external">support <span> @ </span> carbonblack <span> . </span> com</a>
.

</div>

<div id="release-notes" class="section">

### Release Notes <a href="#release-notes" class="headerlink" title="Permalink to this headline">¶</a>

</div>

</div>

<div id="v1-0-0" class="section">

## v1.0.0 <a href="#release-notes" class="headerlink" title="Permalink to this headline">¶</a>

-   Bug

    > <div>
    >
    > -   \[CB-28\] - IOC reports issue “NoneType” not iterable
    >
    > </div>

-   New Feature

    > <div>
    >
    > -   \[CB-17\] - phcb - Search Action
    > -   \[CB-18\] - File Download Action
    > -   \[CB-19\] - Threat Feed Action
    > -   \[CB-20\] - Live Response Action
    > -   \[CB-21\] - Connectivity Test
    >
    > </div>

-   Improvement

    > <div>
    >
    > -   \[CB-22\] - Asset Configuration Clarity
    > -   \[CB-23\] - Get File Metadata Action
    > -   \[CB-24\] - update table output for run_query
    > -   \[CB-25\] - Update filename on file vault upload
    > -   \[CB-26\] - Phantom Documentation
    > -   \[CB-27\] - Use current timestamp when updating API
    > -   \[CB-29\] - Cosmetic Brand Alignment
    > -   \[CB-31\] - Live Response - object format
    >
    > </div>

<div id="action-requirements" class="section">

### Action Requirements <a href="#action-requirements" class="headerlink" title="Permalink to this headline">¶</a>

</div>

</div>

<div id="action-behaviour" class="section">

### Action Behaviour <a href="#action-requirements" class="headerlink" title="Permalink to this headline">¶</a>

If there are multiple contains (e.g. hash, ip, domain, url) in the output datapath, and the
contextual action gets triggered from that datapath, then, if the target action has multiple input
parameters of all the above mentioned types, that value will be populated in all the input
parameters of the target action.

</div>

<div id="live-response" class="section">

## Live Response <a href="#live-response" class="headerlink" title="Permalink to this headline">¶</a>

To fully work correctly, the live response action requires the lr_api_id, the lr_api_secret_key, and
the api_url.

</div>

<div id="all-other-actions" class="section">

## All Other Actions <a href="#all-other-actions" class="headerlink" title="Permalink to this headline">¶</a>

All other actions require api_id, api_secret_key, base_url, and org_key.

</div>

</div>

</div>

</div>

<div class="clearer">

</div>

</div>

<div class="footer">

</div>


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a ThreatHunter asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | PSC Console URL
**api\_url** |  optional  | string | PSC API URL
**api\_secret\_key** |  required  | password | PSC API Secret Key \(API Key\)
**lr\_api\_secret\_key** |  optional  | password | Live Response API Secret Key
**api\_id** |  required  | string | PSC API ID \(Connector ID\)
**lr\_api\_id** |  optional  | string | Live Response API ID
**org\_key** |  required  | string | PSC Organization Key
**feed\_type** |  required  | string | Feed Access Type

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get file](#action-get-file) - Download a file and add it to the vault  
[get file metadata](#action-get-file-metadata) - Get metadata of a file  
[run query](#action-run-query) - Invoke a search for process information  
[live response](#action-live-response) - Take action on the remote endpoint  
[get single feed](#action-get-single-feed) - Get feed info for a single feed  
[delete single feed](#action-delete-single-feed) - Delete single feed  
[get feed reports](#action-get-feed-reports) - Get reports for a single feed  
[get all feeds](#action-get-all-feeds) - Get a list of feeds available  
[create report ioc](#action-create-report-ioc) - Add an IOC to a report  
[delete ioc value](#action-delete-ioc-value) - Delete IOC value from a report  
[delete report ioc](#action-delete-report-ioc) - Remove an IOC from a report  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

Endpoint\: /threathunter/feedmgr/healthcheck

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get file'
Download a file and add it to the vault

Type: **investigate**  
Read only: **True**

Endpoint\: /threathunter/feedmgr/healthcheck

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_hash\_sha256** |  required  | Hash of file/sample to download | string |  `sha256`  `hash` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_hash\_sha256 | string |  `sha256`  `hash` 
action\_result\.data\.\*\.file\_details\.architecture | string | 
action\_result\.data\.\*\.file\_details\.available\_file\_size | numeric |  `file size` 
action\_result\.data\.\*\.file\_details\.charset\_id | numeric | 
action\_result\.data\.\*\.file\_details\.comments | string | 
action\_result\.data\.\*\.file\_details\.company\_name | string | 
action\_result\.data\.\*\.file\_details\.copyright | string | 
action\_result\.data\.\*\.file\_details\.file\_available | boolean | 
action\_result\.data\.\*\.file\_details\.file\_description | string | 
action\_result\.data\.\*\.file\_details\.file\_size | numeric |  `file size` 
action\_result\.data\.\*\.file\_details\.file\_version | string |  `cbthreathunter file version` 
action\_result\.data\.\*\.file\_details\.internal\_name | string |  `file name` 
action\_result\.data\.\*\.file\_details\.lang\_id | numeric | 
action\_result\.data\.\*\.file\_details\.md5 | string |  `md5` 
action\_result\.data\.\*\.file\_details\.original\_filename | string |  `file name` 
action\_result\.data\.\*\.file\_details\.os\_type | string | 
action\_result\.data\.\*\.file\_details\.private\_build | string | 
action\_result\.data\.\*\.file\_details\.product\_description | string | 
action\_result\.data\.\*\.file\_details\.product\_name | string | 
action\_result\.data\.\*\.file\_details\.product\_version | string |  `cbthreathunter product version` 
action\_result\.data\.\*\.file\_details\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.file\_details\.special\_build | string | 
action\_result\.data\.\*\.file\_details\.trademark | string | 
action\_result\.data\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.vault\_id | string |  `vault id` 
action\_result\.summary\.file\_type | string | 
action\_result\.summary\.name | string |  `file name` 
action\_result\.summary\.vault\_id | string |  `vault id` 
action\_result\.message | string | 
summary\.file\_type | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.vault\_id | string |   

## action: 'get file metadata'
Get metadata of a file

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_hash\_sha256** |  required  | Hash of file/sample to download | string |  `sha256`  `hash` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_hash\_sha256 | string |  `sha256`  `hash` 
action\_result\.data\.\*\.architecture | string | 
action\_result\.data\.\*\.available\_file\_size | numeric |  `file size` 
action\_result\.data\.\*\.charset\_id | numeric | 
action\_result\.data\.\*\.comments | string | 
action\_result\.data\.\*\.company\_name | string | 
action\_result\.data\.\*\.copyright | string | 
action\_result\.data\.\*\.file\_available | boolean | 
action\_result\.data\.\*\.file\_description | string | 
action\_result\.data\.\*\.file\_hash\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.file\_size | numeric |  `file size` 
action\_result\.data\.\*\.file\_version | string |  `cbthreathunter file version` 
action\_result\.data\.\*\.internal\_name | string |  `file name` 
action\_result\.data\.\*\.lang\_id | numeric | 
action\_result\.data\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.original\_filename | string |  `file name` 
action\_result\.data\.\*\.os\_type | string | 
action\_result\.data\.\*\.private\_build | string | 
action\_result\.data\.\*\.product\_description | string | 
action\_result\.data\.\*\.product\_name | string | 
action\_result\.data\.\*\.product\_version | string |  `cbthreathunter product version` 
action\_result\.data\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.special\_build | string | 
action\_result\.data\.\*\.trademark | string | 
action\_result\.summary\.status | string | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.file\_type | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run query'
Invoke a search for process information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**process\_name** |  optional  | The process name | string |  `file name` 
**hash** |  optional  | The hash of the process | string |  `hash`  `sha256`  `md5` 
**ip** |  optional  | The remote IPv4 address of the process | string |  `ip` 
**domain** |  optional  | The domain of the process | string |  `domain` 
**max\_results** |  optional  | Maximum number of results to return | numeric | 
**search\_operator** |  optional  | Logically, AND or OR | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.parameter\.hash | string |  `hash`  `sha256`  `md5` 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.max\_results | numeric | 
action\_result\.parameter\.process\_name | string |  `file name` 
action\_result\.parameter\.search\_operator | string | 
action\_result\.data\.\*\.backend\_timestamp | string | 
action\_result\.data\.\*\.childproc\_count | numeric | 
action\_result\.data\.\*\.crossproc\_count | numeric | 
action\_result\.data\.\*\.device\_id | numeric |  `cbthreathunter device id` 
action\_result\.data\.\*\.device\_name | string |  `host name` 
action\_result\.data\.\*\.device\_policy\_id | numeric | 
action\_result\.data\.\*\.device\_timestamp | string | 
action\_result\.data\.\*\.filemod\_count | numeric | 
action\_result\.data\.\*\.index\_class | string | 
action\_result\.data\.\*\.modload\_count | numeric | 
action\_result\.data\.\*\.netconn\_count | numeric | 
action\_result\.data\.\*\.org\_id | string | 
action\_result\.data\.\*\.parent\_guid | string | 
action\_result\.data\.\*\.parent\_pid | numeric | 
action\_result\.data\.\*\.partition\_id | numeric | 
action\_result\.data\.\*\.process\_guid | string | 
action\_result\.data\.\*\.process\_hash | string |  `sha256` 
action\_result\.data\.\*\.process\_hash\_md5 | string |  `md5` 
action\_result\.data\.\*\.process\_hash\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.process\_name | string |  `file path`  `file name` 
action\_result\.data\.\*\.process\_pid | numeric | 
action\_result\.data\.\*\.process\_terminated | boolean | 
action\_result\.data\.\*\.process\_username | string |  `user name` 
action\_result\.data\.\*\.regmod\_count | numeric | 
action\_result\.data\.\*\.scriptload\_count | numeric | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'live response'
Take action on the remote endpoint

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | Device ID to act upon | string |  `cbthreathunter device id` 
**command** |  required  | Command to execute | string | 
**object** |  optional  | Command object | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.command | string | 
action\_result\.parameter\.device\_id | string |  `cbthreathunter device id` 
action\_result\.parameter\.object | string | 
action\_result\.data\.\*\.command\_line | string |  `file name`  `file path` 
action\_result\.data\.\*\.create\_time | numeric | 
action\_result\.data\.\*\.parent | numeric | 
action\_result\.data\.\*\.parent\_create\_time | numeric | 
action\_result\.data\.\*\.path | string |  `path`  `file name` 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.sid | string |  `sid` 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.summary\.status | string | 
action\_result\.summary\.total\_objects | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get single feed'
Get feed info for a single feed

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**feed\_id** |  required  | ID of the feed | string |  `cbthreathunter feed id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.feed\_id | string |  `cbthreathunter feed id` 
action\_result\.data\.\*\.access | string | 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.id | string |  `cbthreathunter feed id` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.owner | string | 
action\_result\.data\.\*\.provider\_url | string |  `url` 
action\_result\.data\.\*\.source\_label | string | 
action\_result\.data\.\*\.summary | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.file\_type | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete single feed'
Delete single feed

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**feed\_id** |  required  | ID of the feed | string |  `cbthreathunter feed id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.feed\_id | string |  `cbthreathunter feed id` 
action\_result\.data\.\*\.id | string |  `cbthreathunter feed id` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.file\_type | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get feed reports'
Get reports for a single feed

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**feed\_id** |  required  | ID of the feed | string |  `cbthreathunter feed id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.feed\_id | string |  `cbthreathunter feed id` 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | string |  `cbthreathunter report id`  `md5` 
action\_result\.data\.\*\.indicators\.\*\.type | string | 
action\_result\.data\.\*\.indicators\.\*\.values | string |  `domain`  `ip`  `email`  `url`  `hash`  `string` 
action\_result\.data\.\*\.iocs | string | 
action\_result\.data\.\*\.iocs\_v2\.\*\.field | string | 
action\_result\.data\.\*\.iocs\_v2\.\*\.id | string |  `cbthreathunter ioc id` 
action\_result\.data\.\*\.iocs\_v2\.\*\.link | string | 
action\_result\.data\.\*\.iocs\_v2\.\*\.match\_type | string | 
action\_result\.data\.\*\.iocs\_v2\.\*\.values | string |  `domain`  `ip`  `email`  `url`  `hash`  `string` 
action\_result\.data\.\*\.link | string | 
action\_result\.data\.\*\.severity | numeric |  `severity` 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.timestamp | numeric | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.visibility | string | 
action\_result\.summary\.total\_feed\_reports | numeric | 
action\_result\.message | string | 
summary\.file\_type | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get all feeds'
Get a list of feeds available

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**include\_public** |  optional  | Should public feeds be included | boolean |  `boolean` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.include\_public | string |  `boolean` 
action\_result\.data\.\*\.access | string | 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.id | string |  `cbthreathunter feed id` 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.owner | string | 
action\_result\.data\.\*\.provider\_url | string |  `url` 
action\_result\.data\.\*\.source\_label | string | 
action\_result\.data\.\*\.summary | string | 
action\_result\.summary\.total\_feeds | numeric | 
action\_result\.message | string | 
summary\.file\_type | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create report ioc'
Add an IOC to a report

Type: **generic**  
Read only: **False**

At least one parameter value needs to be provided to execute the action and before executing the action the container type should be changed from 'default' to 'case'\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash\_ioc** |  optional  | Hash IOC of the process | string |  `hash`  `sha256` 
**ipv6\_ioc** |  optional  | IPv6 IOC of the device or process | string |  `ipv6` 
**ipv4\_ioc** |  optional  | IPv4 IOC of the device or process | string |  `ip` 
**domain\_ioc** |  optional  | Domain IOC of the process | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain\_ioc | string |  `domain` 
action\_result\.parameter\.hash\_ioc | string |  `hash`  `sha256` 
action\_result\.parameter\.ipv4\_ioc | string |  `ip` 
action\_result\.parameter\.ipv6\_ioc | string |  `ipv6` 
action\_result\.data\.\*\.field | string | 
action\_result\.data\.\*\.id | string |  `cbthreathunter ioc id` 
action\_result\.data\.\*\.link | string | 
action\_result\.data\.\*\.match\_type | string | 
action\_result\.data\.\*\.values | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete ioc value'
Delete IOC value from a report

Type: **generic**  
Read only: **False**

At least one parameter value needs to be provided to execute the action and before executing the action the container type should be changed from 'default' to 'case'

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash\_ioc** |  optional  | Hash IOC of the process | string |  `hash`  `sha256` 
**ipv6\_ioc** |  optional  | IPv6 IOC of the device or process | string |  `ipv6` 
**ipv4\_ioc** |  optional  | IPv4 IOC of the device or process | string |  `ip` 
**domain\_ioc** |  optional  | Domain IOC of the process | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain\_ioc | string |  `domain` 
action\_result\.parameter\.hash\_ioc | string |  `hash`  `sha256` 
action\_result\.parameter\.ipv4\_ioc | string |  `ip` 
action\_result\.parameter\.ipv6\_ioc | string |  `ipv6` 
action\_result\.data\.\*\.field | string | 
action\_result\.data\.\*\.id | string |  `cbthreathunter ioc id` 
action\_result\.data\.\*\.link | string | 
action\_result\.data\.\*\.match\_type | string | 
action\_result\.data\.\*\.values | string |  `ip`  `sha256` 
action\_result\.summary\.deleted\_ioc\_values | string | 
action\_result\.summary\.undeleted\_ioc\_values | string | 
action\_result\.summary\.unavailable\_iocs\_field\_values | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete report ioc'
Remove an IOC from a report

Type: **generic**  
Read only: **False**

Before executing the action the container type should be changed from 'default' to 'case'\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**iocid** |  required  | The IOC ID to remove | string |  `cbthreathunter ioc id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.iocid | string |  `cbthreathunter ioc id` 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.field | string | 
action\_result\.data\.\*\.id | string |  `cbthreathunter ioc id` 
action\_result\.data\.\*\.link | string | 
action\_result\.data\.\*\.match\_type | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.provider\_url | string |  `url` 
action\_result\.data\.\*\.values | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.file\_type | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 