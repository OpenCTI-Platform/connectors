# Tagger Enrichment Connector

This is an internal enrichment connector that apply labels to objects based on specific regular expressions rules and scopes (reports, observables, etc.).

## Problem

The reason why this connector can be useful in your workflow is due the fact that multi information sources come with their own labels and after some time, the labels on your opencti will not be useful anymore because there is no structure or common understanding.

## Solution

1. Your team should define a set of labels that everyone understand and agree to apply to different types of objects in OpenCTI. Those labels should be created manually in the platform.
2. After that definition and aggreement, you can also discuss with your team the rules that should be applied to each objects that arrive in the OpenCTI to automatically apply a label or more on them; then
4. Configure the Tagger with those rules and turn it on.
4. Please note that you must actively block all connectors (except Tagger) from creating labels on the platform.

## Configuration

In order to configure the tagger logic, use the file `definitions.json` knowing the following concepts:

* scope: opencti scope like the ones that are used to configure `CONNECTOR_SCOPE`. Please note that if you are configuring report tagger rule, you must also specify `Report` in `CONNECTOR_SCOPE` setting.
* label: the actual label that you want to associate to the object
* search: the regular expression to identify the objects that need the label
* attributes: list of attributes of the object where the search will be applied

As soon as you have the `definitions.json` configured, please execute the following command:
```
jq -c . < src/definitions.json
```

The output of the above command should use to set the value of `TAGGER_DEFINITIONS` between single quote char `'`, like you can find in `.env.dist` file