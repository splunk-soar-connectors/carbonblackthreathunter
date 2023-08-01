
<div class="document">

<div class="documentwrapper">

<div class="body" role="main">

<div id="usage-notes" class="section">

# Usage notes <a href="#usage-notes" class="headerlink" title="Permalink to this headline">¶</a>

<div class="toctree-wrapper compound">



<div id="threat-feed-management" class="section">

## Threat Feed Management <a href="#threat-feed-management" class="headerlink" title="Permalink to this headline">¶</a>

Threat feed actions support the use of the v2 API specification. They require an organization key to
work correctly. A single threat feed is created per Phantom instance. Additional reports should be
created and assigned to the feed by using the Case action within Phantom. Each report will contain
the values for the artifacts in the case. The report id in Carbon Black ThreatHunter is assigned to
the case id. Independent actions can also be taken directly in Phantom using playbooks.

<div id="documentation" class="section">

### Documentation <a href="#documentation" class="headerlink" title="Permalink to this headline">¶</a>

For product information, please refer to <https://www.carbonblack.com/products/cb-threathunter/> .
For help with APIs or developer needs, please refer to <https://developer.carbonblack.com/> .



<div id="support" class="section">

### Support <a href="#support" class="headerlink" title="Permalink to this headline">¶</a>

Please contact Carbon Black Support for any issues relating to this app. Support can be emailed via
<a href="mailto:support%40carbonblack.com" class="reference external">support <span> @ </span> carbonblack <span> . </span> com</a>
.



<div id="release-notes" class="section">

### Release Notes <a href="#release-notes" class="headerlink" title="Permalink to this headline">¶</a>





<div id="v1-0-0" class="section">

## v1.0.0 <a href="#release-notes" class="headerlink" title="Permalink to this headline">¶</a>

-   Bug

    > 
    >
    > -   \[CB-28\] - IOC reports issue “NoneType” not iterable
    >
    > 

-   New Feature

    > 
    >
    > -   \[CB-17\] - phcb - Search Action
    > -   \[CB-18\] - File Download Action
    > -   \[CB-19\] - Threat Feed Action
    > -   \[CB-20\] - Live Response Action
    > -   \[CB-21\] - Connectivity Test
    >
    > 

-   Improvement

    > 
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
    > 

<div id="action-requirements" class="section">

### Action Requirements <a href="#action-requirements" class="headerlink" title="Permalink to this headline">¶</a>





<div id="action-behaviour" class="section">

### Action Behaviour <a href="#action-requirements" class="headerlink" title="Permalink to this headline">¶</a>

If there are multiple contains (e.g. hash, ip, domain, url) in the output datapath, and the
contextual action gets triggered from that datapath, then, if the target action has multiple input
parameters of all the above mentioned types, that value will be populated in all the input
parameters of the target action.



<div id="live-response" class="section">

## Live Response <a href="#live-response" class="headerlink" title="Permalink to this headline">¶</a>

To fully work correctly, the live response action requires the lr_api_id, the lr_api_secret_key, and
the api_url.



<div id="all-other-actions" class="section">

## All Other Actions <a href="#all-other-actions" class="headerlink" title="Permalink to this headline">¶</a>

All other actions require api_id, api_secret_key, base_url, and org_key.









<div class="clearer">





<div class="footer">


