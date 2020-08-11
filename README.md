# vulniq-tsunami-plugin
Tsunami vulnerability detector plugin using VulnIQ APIs

***
Please note that this is an example plugin, not intended for production use.
An official version will be released for VulnIQ customers when/if tsunami gains traction.
This example version supports reporting vulnerabilities only for Apache Httpd and Elasticsearch.
***

## What Does This Plugin Do?
This plugin reports vulnerabilities based on detected software versions only.
It simply queries VulnIQ APIs and pass the software name and version to obtain list of 
vulnerabilities affecting the given version. 

## Compiling and Packaging
This project uses maven (unlike tsunami itself which uses gradle).
`mvn clean package` will generate vulniq-tsunami-plugin-1.0-SNAPSHOT.jar and 
tsunami-with-vulniq-plugin.zip files under `target` folder.

vulniq-tsunami-plugin-1.0-SNAPSHOT.jar is the VulnIQ plugin which you can deploy into your existing tsunami instance.

Unzipping tsunami-with-vulniq-plugin.zip will give you a runnable tsunami instance with only the VulnIQ plugin installed.
This package is intended for quick testing and does not contain any other plugins except the nmap port scanning plugin.

## Configuration
See conf/tsunami.yaml file. You need to add a VulnIQ access token in this file before running tsunami.

## Running The Bundled Tsunami Instance
You can run the following command to scan 127.0.0.1
`bin/tsunami.sh  --ip-v4-target=127.0.0.1 --scan-results-local-output-format=JSON --scan-results-local-output-filename=output.json`

This will generate output.json file in the **bin** folder. You must have nmap installed for this to work.


## More information
Contact info@vulniq.com if you have any questions and/or feedback.