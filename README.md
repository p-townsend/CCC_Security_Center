# CCC_Security_Center
# Outline

[Notes](https://www.notion.so/Notes-2656a442a47280e4a88cd36b0b7f7dd6?pvs=21)

## 1. Goals of this project

1.1

## 2. Getting Set-up

**2.1 Python Environment Set Up**

**2.1.1 Recommended to use Python Version 3.10 or later for support and stability**

- `python --version` to check your current version

**2.1.2 Set up a virtual environment**

- A virtual environment keeps your project’s Python libraries isolated so they don’t conflict with other projects or system packages.
- Create your environment: `python3 -m venv .venv`
- Activate your environment:
    - **Windows:** `.venv\Scripts\activate`
    - **macOS/Linux:** `source .venv/bin/activate`

**2.1.3 Required Libraries**

- **requests** — for making API calls
- **python-dotenv** — for loading environment variables from a `.env` file
- Install and Confirmation
    - `pip install requests python-dotenv jsonpath-ng`
    - `pip list`

**2.2 API Key Security**

- Getting your API Key from Bitsight

![Screenshot 2025-09-04 165827.png](attachment:a80d2cb5-1b7a-493f-bb62-8d3e418b9d74:Screenshot_2025-09-04_165827.png)

![Screenshot 2025-09-04 165847.png](attachment:f3bdfed1-5c36-412b-b07b-01a7595456f0:Screenshot_2025-09-04_165847.png)

![Screenshot 2025-09-04 165904.png](attachment:f0cce4e0-9683-44ec-9340-f9aa98bb5617:Screenshot_2025-09-04_165904.png)

![Screenshot 2025-09-04 165839.png](attachment:f8b1023c-ff41-4217-93fb-8cff2640521f:Screenshot_2025-09-04_165839.png)

![Screenshot 2025-09-04 165854.png](attachment:ba8ab4f6-95d6-4535-bb9e-244cba8a9929:Screenshot_2025-09-04_165854.png)

- **Never** hardcode API keys directly in your Python scripts. Store them securely using environment variables.
1. Create a `.env` file in the root of the project
    - `API_KEY = [INSERT YOUR API TOKEN]`
2. Load into Python
    
    ```python
    from dotenv import load_dotenv
    import os
    
    load_dotenv()  # Load environment variables from .env file
    
    api_key = os.getenv("API_KEY")
    ```
    
3. Add `.env` to `.gitignore`
    - Prevent your API keys from being pushed to GitHub
        
      '''# Ignore Python virtual environments
      venv/
      .venv/

      # Ignore environment variable files (API keys, secrets, etc.)
      .env
      .env.*

      # Ignore Python cache files
      __pycache__/
      *.py[cod]
      *.pyo'''

        

**2.3 Parsing JSON strings**

- The expected output will give you a JSON file, essentially just a GIANT, sort of annoying, nested dictionary
    - MAKE SURE TO `import json`
    - Parsing JSON files in Python: https://www.geeksforgeeks.org/python/parsing-json-nested-dictionary-using-python/
    - It might also be worth install (AND import `parse` from) `jsonpath-ng` to make traversing it easier: `pip install jsonpath-ng`
- To try and find the depth, you can also use nested JSON decoders such as https://nextjson.com/ or https://jsonformatter.org/json-parser
    - this will just help you view where the information you want is because there is so much nesting in these JSON files

## 3. Core Functionalities

**3.1 Open Port Identification**

- Documentation: https://help.bitsighttech.com/hc/en-us/articles/17384491574039-GET-Open-Ports-Finding-Details, https://help.bitsighttech.com/hc/en-us/articles/360022913734-GET-Finding-Details
- **Concept:** Open Port Identification involves leveraging the Bitsight API to discover and analyze publicly accessible network ports on an organization's assets.
    - The goal is to provide a comprehensive overview of an organization's external attack surface related to open ports, including details such as the specific port number, associated services, and any identified vulnerabilities (CVEs).
- **Implementation Details:** The implementation involves making API calls to the Bitsight platform to retrieve open port findings.
    - This includes constructing appropriate queries with parameters such as `risk_vector=open_ports` and applying advanced filters for `affects_rating`, `grade`, `vulnerabilities`, `first_seen`, `last_seen`, and CVSS scores.
    - The retrieved JSON data will then be parsed to extract relevant information like asset IP, port number, service detected, and associated CVEs.
    - This data will be presented in a structured and easily digestible format, potentially with visualizations to highlight critical findings
- **Parameters & Expected Output:**
    - Query Options: https://help.bitsighttech.com/hc/en-us/articles/360022913734-GET-Finding-Details#parameters
- **Advanced Filtering for Open Port Findings:**
    - **Impact on Rating:** Filtering by `affects_rating: true`.
    - **Bitsight Grade:** Filtering by `"BAD"`, `"WARN"`, `"FAIR"`.
    - **Vulnerability Association:** Filtering for `vulnerabilities: NOT NULL`.
    - **Temporal Filtering:** Filtering by `first_seen` and `last_seen` dates.
    - **CVSS Score:** Filtering by CVSS score range.
- **Example Output:**
    
    
    ```json
    {
      "links":{
        "next":"https://api.bitsighttech.com/ratings/v1/companies/a940bb61-33c4-42c9-9231-c8194c305db3/findings?limit=100&offset=100&risk_vector=open_ports",
        "previous":null
      },
      "count":7988,
      "results":[
        […] // [f for f in results if f.get("affects_rating")]
        {
          "temporary_id":"A9Jq47BBje36fc970103a54dec7a1a4944622d0f71",
          "affects_rating":true, // Keep the filter as TRUE
          "assets":[
            {
              "asset":"23.102.37.182", // Shows us WHERE the open port is
              "identifier":null,
              "category":"critical",
              "importance":0.36,
              "is_ip":true
            }
          ],
          "details":{
            "cvss":{ // can filter by certain ranges of cvss scores
              "base":[
                7.5
              ]
            },
            "check_pass":"",
            "diligence_annotations":{
              "message":"Detected service: AMQP",
              "CPE":[
                "a:vmware:rabbitmq:3.9.13"
              ],
              "Product":"RabbitMQ",
              "Version":"3.9.13",
              "transport":"tcp"
            },
            "geo_ip_location":"IE",
            "country":"Ireland",
            "grade":"WARN", // can sort by "BAD", "WARN", and MAYBE "FAIR"
            "remediations":[
              {
                "message":"Detected service: AMQP",
                "help_text":"This port was observed running the Advanced Messaging Queuing Protocol (AMQP), which is used for sending messages between distributed systems.",
                "remediation_tip":"Create company firewall rules to only allow approved AQMP destinations or block the port entirely in the company edge network infrastructure and tunnel AQMP requests through a Virtual Private Network (VPN)."
              }
            ],
            "sample_timestamp":"2023-09-06T19:38:57Z",
            "vulnerabilities":[ // can filter by ports which known vulnerabilities
              {
                "name":"CVE-2022-31008",
                "alias":"",
                "display_name":"CVE-2022-31008",
                "description":"RabbitMQ is a multi-protocol messaging and streaming broker. In affected versions the shovel and federation plugins perform URI obfuscation in their worker (link) state. The encryption key used to encrypt the URI was seeded with a predictable secret. This means that in case of certain exceptions related to Shovel and Federation plugins, reasonably easily deobfuscatable data could appear in the node log. Patched versions correctly use a cluster-wide secret for that purpose. This issue has been addressed and Patched versions: `3.10.2`, `3.9.18`, `3.8.32` are available. Users unable to upgrade should disable the Shovel and Federation plugins.",
                "remediation_tip":"",
                "confidence":"LOW",
                "cvss":{
                  "base":7.5
                },
                "severity":"Material"
              }
            ],
            "dest_port":5672, // Shows us which port is open
            // could hardcode a dictionary explaining what the common ports are so we can have the program automatically tell us what it is and we can know WHY it is a concern
            "rollup_end_date":"2023-09-06",
            "rollup_start_date":"2023-08-31",
            "searchable_details":"Detected service: AMQP,tcp,RabbitMQ"
          },
          "evidence_key":"23.102.37.182:5672",
          "first_seen":"2023-08-31", // Find the first time the open port was found
          "last_seen":"2023-09-06", // Find the last time the open port was seen; can be used to look for port STILL open
          "related_findings":[ ],
          "risk_category":"Diligence",
          "risk_vector":"open_ports",
          "risk_vector_label":"Open Ports",
          "rolledup_observation_id":"No72KfYkacdJk4Cy03TuFg==",
          "severity":6.0,
          "severity_category":"moderate",
          "tags":[ ],
          "remediation_history":{
            "last_requested_refresh_date":"2024-06-19",
              "last_refresh_status_date":"2024-06-23",
              "last_refresh_status_label":"failed",
            "last_refresh_status_reason": "asset_not_found",
              "last_refresh_reason_code":"asset unreachable",
              "last_refresh_requester": "1e10564d-fawa-4331-0000-6f7588b55a98",
            "result_finding_date": null
          },
          "asset_overrides":[ ],
          "duration":null,
          "comments":null,
          "remaining_decay":59,
          "remediated":null
        }
      ]
    }
    ```
    
- **Resume Building Focus:** Highlight skills gained (API Integration, Network Fundamentals, Data Validation, Python Scripting).

**3.2 Bitsight Rating Change Monitoring**

- Documentation: https://help.bitsighttech.com/hc/en-us/articles/7088116583063-GET-Rating-Change-Explanations
- **Concept:** Bitsight Rating Change Monitoring focuses on tracking and analyzing fluctuations in an organization's Bitsight security rating over time.
- The process involves fetching current and historical rating data from the Bitsight API and comparing them to identify significant shifts and their underlying causes.
- **Implementation Details:** The implementation involves regularly querying the API to retrieve rating change explanations.
    - Fetching Current Ratings: Use Bitsight API /insights endpoint for recent security ratings.
    - Comparing with Historical Data: Compare current ratings with stored historical data. → **ADDITIONAL CONSIDERATION:** Creating a new file to be updated with new changes to monitor fluctuations?
- **Parameters & Expected Output:** Inputs (API key, district GUIDs), key fields from Bitsight API (`name`, `rating`, `last_updated`), and example output for rating changes.
    - Inputs:
        - **`api_token`**: For Bitsight API authentication.
        - `company`: Filter changes by specified companies. A comma separated list of GUIDs. **(`%2C%20` is a URL-encoded representation of a comma followed by a space (`,` ) for web addresses)**
        - `date_gte`: Filter changes by date greater or equal to specified date. ISO formatted date.
        - `date_lt`: Filter changes by date lower than the specified date. ISO formatted date
    - Key Fields from Bitsight API (/insights endpoint):
        - `name`: Company/district name.
        - `rating`: Current Bitsight security rating (300-820).
        - `last_updated`: Timestamp of last rating update.
        - `initial_rating`: Rating at start of timeframe.
        - `final_rating`: Rating at end of timeframe.
        - `percentile_change`: Percentage change in rating.
        - `reason`: Explanation for rating change.
    
    ```json
    {
      "links":{
        "next":"https://api.bitsighttech.com/ratings/v1/insights/rating_changes?limit=100&offset=100",
        "previous":null
      },
      "count":111922,
      "results":[
          […]
          {
            "date":"2022-03-24", // You are going to want to filter by certain dates
            // I would probably reccommened using the date_gte option, and choosing a date (in "YYYY-MM-DD" format) you want to start looking from
            // otherwise, it will show you the first 100 rating changes
            "start_score":620, //****
            "end_score":600, //****
            // could possibly add a manual check for specific changes of scores either going up or going down
            "reasons":[
              {
                "start_percentile":60.383198,
                "risk_vector":"pot_exploited", // very good, shows us exactly why the rating changed
                // can also filter with this: e.g. if we want to check for only ratings changed by open ports
                "end_percentile":54.58032
              }
            ],
            "type":"rating-change",
            "company":"a940bb61-33c4-42c9-9231-c8194c305db3" // company guid
    			  // if not searching through a company filter, could run an additional check to automatically give district name
    			  // ADDITIONAL CONSIDERATION: could use GET Portfolio to hard code company names and guids, probably use Swagger UI to just run and manually hard code
        }
      ]
    }
    ```
    
- **Advanced Filtering for Rating Changes:**
    - **Magnitude:** How to filter by points changed (e.g., `> 20` points).
    - **Direction:** Filtering for `increase` or `decrease`.
    - **Timeframe:** Filtering by `today`, `last 7 days`, custom date ranges.
    - **Current Rating Range:** Filtering by current rating score ranges (e.g., `0-500`).
    - **Risk Vector Change:** Highlighting significant changes in specific risk vector scores.
- **Resume Building Focus:** Highlight skills gained (API Integration, Data Analysis, Trend Monitoring, Multi-Client Management).

## 4. Extra Features (Optional + at a later date)

**4.1 CVE Enrichment with NVD API**

- **Concept:** The Bitsight API's open_ports findings provide not only details about open ports but also associated vulnerabilities, including CVE IDs.
    - This allows for direct CVE enrichment by leveraging existing Bitsight data, streamlining the process of identifying and understanding vulnerabilities linked to exposed services.
- **Implementation Details:** Integrate with the Bitsight API to retrieve open_ports findings.
    - Within the JSON response, navigate to the details.vulnerabilities array.
    - For each vulnerability object, extract the name (CVE ID), description, cvss (base score), and remediation_tip.
    - Display this extracted CVE information alongside the open port details to provide a comprehensive view of the exposure.
- **Parameters & Expected Output:** Inputs (CVE ID derived from Bitsight), key fields from NVD API, and example output from NVD API.
    - Inputs: CVE ID (e.g., CVE-YYYY-NNNNN), obtained from Bitsight open_ports findings.
    - Key Fields from NVD API: id, descriptions, metrics (for CVSS scores), references, published, lastModified.
    - Example Output (from NVD API for a CVE):
    
    ```json
    {
      "vulnerabilities": [
        {
          "cve": {
            "id": "CVE-2023-XXXXX",
            "sourceIdentifier": "nvd@nist.gov",
            "published": "2023-01-01T00:00:00.000Z",
            "lastModified": "2023-01-05T12:30:00.000Z",
            "descriptions": [
              {
                "lang": "en",
                "value": "A detailed description of the vulnerability, its impact, and affected components." 
                // this is the primary thing we want to pull
                // when converting the data into user friendly readable information, can put this next to the actual CVE
              }
            ],
            "metrics": {
              "cvssMetricV31": [
                {
                  "source": "nvd@nist.gov",
                  "type": "Primary",
                  "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentialityImpact": "HIGH",
                    "integrityImpact": "HIGH",
                    "availabilityImpact": "HIGH",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL"
                  },
                  "exploitabilityScore": 3.9,
                  "impactScore": 5.9
                }
              ]
            },
            "references": [
              {
                "url": "https://example.com/advisory/CVE-2023-XXXXX",
                "source": "EXAMPLE"
              }
            ]
          }
        }
      ]
    }
    ```
    
- **Resume Building Focus:** Highlight skills gained (Threat Intelligence Integration, Vulnerability Analysis, Data Enrichment).

**4.2 User-Specific Data Access ~~and Authentication~~** (ONCE and IF interns are assigned their specific districts)

- **Concept:** User-Specific Data Access and Authentication is designed to ensure that each intern or user can only access data relevant to their assigned district(s)
    - This feature establishes a secure and controlled environment by implementing robust authentication mechanisms and granular access control based on predefined user-to-district mappings.
- **Implementation Details:**
    - Each intern is associated with a specific district (or multiple districts if applicable) in a mapping stored in a local database or configuration file. This mapping defines what data each user can access.
    - **Authentication Flow:** Interns must log in with their unique credentials (created on first use)
        - The system verifies their identity against the stored user database before granting access.
        - Once authenticated, the system retrieves the intern’s assigned district(s) and initializes a session tied to those permissions.
    - **Session-Based Access Control:** After login, all data requests are filtered based on the intern’s district mapping.
        - Any attempt to request data outside their assigned district is blocked or ignored.
- **Parameters & Expected Output:**
    - **Inputs:** Login credentials (username, password) and session initiation parameters.
    - **Filtering Mechanism:** Post-authentication, the system automatically applies district filters to all subsequent data queries.
    - **Outputs:** Only the subset of data corresponding to the user’s assigned district(s) is returned. Any attempt to access other districts results in no data or an access-denied notification.

## 5. Error Handling (WIP)
