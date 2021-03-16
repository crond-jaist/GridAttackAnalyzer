
# Developer Guide

In this document we provide information to help those researchers
interested in extending the functionality of GridAttackAnalyzer, for
example by adding new smart grid models, new devices or new network
vulnerabilities.


## File Overview

The GridAttackAnalyzer release contains a large number of files, and
we provide an overview below to facilitate further development and
extensions of the software.

```
├── GLM/                                # Folder with power grid models (GLM files)
├── Results/                            # Folder for attack analysis files
│   ├── source.csv                      # Input file for analysis
│   └── Results.csv                     # Output file for analysis
├── Scripts/                            # Folder for scripts used internally
│   ├── AttackGraph.py                  # Construct the attack graph (AG)
│   ├── AttackTree.py                   # Construct the attack tree (AT)
│   ├── Harm.py                         # Construct HARMs using AG and AT
│   ├── NetGen.py                       # Generate IoT network based on attack scenario
│   ├── Network.py                      # Network object and relevant functions
│   ├── Node.py                         # Node object
│   ├── SecurityEvaluator.py            # Conduct security analysis
│   ├── Topology.py                     # Topology object
│   ├── Vulnerability.py                # Vulnerability object and relevant functions
│   ├── glmMap.py                       # Convert power grid model GLM file to graph
│   ├── plotMetrics.py                  # Plot security metrics
│   └── plotResult.py                   # Plot the attack graph
├── GridAttackAnalyzer.py               # Main application GUI file
└── database.json                       # Attack library in JSON format
```


## How to Add New Objects

GridAttackAnalyzer makes it possible to analyze various types of
cyber-attacks on smart grids. These attacks are modeled via
information stored in a database that uses the JSON format to
represent three types of objects:
* Power grid model: Abstraction of a smart grid topology with houses
  grouped in "streets"
* Network device: Abstraction of a smart grid device with a list of
  vulnerabilities associated to it
* Network vulnerability: An IoT device vulnerability represented using
  the CVE format

The database includes three lists of objects, one for each type of
object mentioned above, and is structured as follows:

```
├── "object"                            # JSON object containing the three lists
│   ├── object_id                       # Power grid model list ID
│   │   ├── name                        # Name of the object
│   │   ├── description                 # Power grid model list description
│   │   └── model_list                  # Power grid model list
│   │       ├── list_name               # Model name
│   │       └── streets_and_houses      # Areas and number of houses for each area
│   ├── object_id                       # Devices list ID
│   │   ├── name                        # Name of the object
│   │   ├── description                 # Device list description
│   │   └── devices_list                # Device list
│   │       ├── device_name             # Device name
│   │       ├── CVE_list                # List of vulnerabilities for that device
│   │       └── group                   # Device group
│   └── object_id                       # CVE list ID
│       ├── name                        # Name of the object
│       ├── description                 # CVE list description
│       └── CVE list                    # CVE list
│           ├── CVE                     # CVE ID
│           ├── description             # CVE description
│           ├── CVSS_Base_Score_2.0     # CVSS Base Score 2.0
│           ├── Impact_Subscore         # Impact Subscore
└──         └── Exploitability_Subscore # Exploitability Subscore
```

We present below an example database with three objects: a power grid
model named "IEEE 4 Node", a device named "Smart TV" and a
vulnerability with the ID "CVE-2017-9944".

```
{
  "type": "attack_tree_library",
  "version": "1.0",
  "created": "2021-01-01",
  "object": [
    {
      "object_id": 0,
      "name": "Power Grid Model",
      "description": "Power Grid Model",
      "model_list":[
        {
          "list_name": "IEEE 4 Node",
          "streets_and_houses": [
            {
              "A": 5,
              "B": 6,
              "C": 8,
              "D": 12
            }
          ]
        },
    },
    {
      "object_id": 1,
      "name": "Devices",
      "description": "Devices List",
      "devices_list":[
        {
          "device_name": "Smart TV",
          "CVE_list": ["CVE-2019-9871","CVE-2019-11336", "CVE-2019-12477", "CVE-2018-13989", "CVE-2020-9264"],
          "group": 1
        }
      ]
    },
    {
      "object_id": 2,
      "name": "CVE",
      "description": "CVE List",
      "CVE_list":[
        {
          "CVE": "CVE-2017-9944",
          "description": "Allow an unauthenticated remote attacker to perform administrative operations over the network",
          "CVSS_Base_Score_2.0": 10,
          "Impact_Subscore": 10,
          "Exploitability_Subscore": 10
        }
        ]
    }
    ]
}
```

In order to add a new object to the database, for example a new device
or a new vulnerability, one simply has to edit the database file,
named `database.json`, and add the new object into the appropriate
list. Once GridAttackAnalyzer is restarted, it will load the new
database and the new objects become usable in analysis scenarios.

### Notes

* For power grid models, a corresponding GLM file needs to be placed
  in the `GLM/` directory in order to make topology visualization
  possible.
* For network devices, after adding a new device into the database the
  file `Scripts/NetGen.py` needs to be edited to make sure that the
  new device is integrated with the built-in network model.
* The built-in network model cannot be changed without modifying the
  source code; those interested in updating it should edit the file
  `Scripts/NetGen.py` mentioned above.
