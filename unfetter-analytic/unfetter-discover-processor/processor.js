var JSONAPISerializer = require("jsonapi-serializer").Serializer;

/*eslint no-console: "off"*/
const fs = require("fs");
const http = require("http");
const process = require("process");

const typePathMapping = {
    attack_patterns: "attack-patterns",
    campaigns: "campaigns",
    courses_of_action: "course-of-actions",
    indicators: "indicators",
    relationships: "relationships",
    malware: "malwares",
    marking_definitions: "marking-definitions",
    reports: "reports",
    threat_actors: "threat-actors",
    tools: "tools"
};

let port = 3000;
if (process.argv.indexOf("-p") != -1) {
    port = process.argv[process.argv.indexOf("-p") + 1];
}
let host = "cti-stix-store";
if (process.argv.indexOf("-h") != -1) {
    host = process.argv[process.argv.indexOf("-h") + 1];
}

const stixContentType = "application/vnd.api+json";
const defaultOptions = {
    host: host,
    port: port,
    path: "/cti-stix-store-api",
    method: "POST",
    headers: {
        "Accept": stixContentType,
        "Content-Type": stixContentType
    }
};

/**
 * Process File containing JSON of STIX Bundle Object
 *
 */
function processFile(filename) {
    console.log(`Reading File [${filename}]`);
    const resources = readJson(filename);
    if (resources) {
        processBundleRecords(resources);
    }
}

/**
 * Read JSON from File Path
 *
 * @param {string} filePath Path of file for parsing
 * @returns {Object} Object parsed from File Path
 */
function readJson(filePath) {
    let json;

    if (fs.existsSync(filePath)) {
        let string = fs.readFileSync(filePath, "utf-8");
        json = JSON.parse(string);
    } else {
        console.log(`File Path [${filePath}] not found`);
    }

    return json;
}

/**
 * Process Bundle of Records
 *
 * @param {Object} bundle STIX Bundle Object
 */
function processBundleRecords(bundle) {
    for (var key in typePathMapping) {
        let type = typePathMapping[key];
        let records = bundle[key];
        if (records) {
            postRecords(records, type);
        }
    }

    if (bundle.custom_objects) {
        if (bundle.custom_objects.length) {
            const firstObject = bundle.custom_objects[0];
            const resourcePath = `${firstObject.type}s`;
            postRecords(bundle.custom_objects, resourcePath);
        }
    }
}


/**
 * Post Records
 *
 * @param {Array} records Array of records for sending
 * @param {string} resourcePath Relative resource path to server
 */
function postRecords(records, resourcePath) {
    let options = Object.assign({}, defaultOptions);
    options.path = `${options.path}/${resourcePath}`;

    console.log(`Processing Started: Records [${records.length}] Type [${resourcePath}]`);
    let created = 0;
    let processed = 0;
    let failed = 0;
    var attributesList = [];

    records.forEach(function (record) {
        for (let propertyKey in record) {
            attributesList.push(propertyKey);
        }
        var patternSerializer = new JSONAPISerializer(resourcePath, {
            attributes: attributesList,
            keyForAttribute: "snake_case"
        });
        record = patternSerializer.serialize(record);

        let request = http.request(options, function (response) {
            processed++;
            if (response.statusCode == 201) {
                created++;
            } else {
                failed++;
                console.error(`Type [${resourcePath}] Name [${record.data.name}] ID [${record.id}] Status [${response.statusCode}]`);

                let body;
                response.on("data", function (data) {
                    if (data) {
                        body += data;
                    }
                });
                response.on("end", function () {
                    console.error(`Type [${resourcePath}] Name [${record.name}] ID [${record.id}] Response [${body}]`);
                });
            }

            if (processed === records.length) {
                console.log(`Processing Completed: Records [${processed}] Created [${created}] Failed [${failed}] Type [${resourcePath}]`);
            }
        });

        let string = JSON.stringify(record);
        request.write(string);

        request.end();
    });
}

/**
 * Run processes files specified as arguments
 *
 */

function run() {
    setTimeout(run2, 9000);
}

function run2() {
    console.log("Starting processor.js");

    if (process.argv.indexOf("-j") == -1) {
        console.error("The -j argument is required");
    }
    else
    {
        for (var i = process.argv.indexOf("-j") + 1, len = process.argv.length; i < len; i++) {
            if (i > 1) {
                processFile(process.argv[i]);
            }
        }
    }
}



run();
