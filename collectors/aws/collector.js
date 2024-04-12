/*********************
 Collector - The collector will query AWS APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.

 Arguments:
 - AWSConfig: If using an access key/secret, pass in the config object. Pass null if not.
 - settings: custom settings for the scan. Properties:
 - skip_regions: (Optional) List of regions to skip
 - api_calls: (Optional) If provided, will only query these APIs.
 - Example:
 {
     "skip_regions": ["us-east-2", "eu-west-1"],
     "api_calls": ["EC2:describeInstances", "S3:listBuckets"]
 }
 - callback: Function to call when the collection is complete
 *********************/


var async = require('async');
var helpers = require(__dirname + '/../../helpers/aws');
var collectors = require(__dirname + '/../../collectors/aws');
var collectData = require(__dirname + '/../../helpers/shared.js')
///WALKED THROUGH ALL PLUGINS AND RAN THE FIRST PLUGIN IN EACH FOLDER
//for those not working we will need to click on each plugin and look at the service needs.
//for those with no SDK test, we will need to look at the api call and see if they have moved to another sdk
//prioritize fixing call 1 issues **DONE**
//call 1 now called "call 347"
//call 2 now called "call357"
var AccessAnalyzer = require("@aws-sdk/client-accessanalyzer"); //update working
var ACM = require("@aws-sdk/client-acm"); //missing package //udpate working
var APIGateway = require ("@aws-sdk/client-api-gateway"); //update working
var Appflow = require ("@aws-sdk/client-appflow"); //missing package //not working //update working
var AppMesh = require ("@aws-sdk/client-app-mesh"); //update working
var AppRunner = require ("@aws-sdk/client-apprunner"); //update working
var Athena = require ("@aws-sdk/client-athena"); //update working
var AuditManager = require ("@aws-sdk/client-auditmanager"); //update UNKOWN Results
var AutoScaling = require ("@aws-sdk/client-auto-scaling");//update appTierIamRole hit call 2! new call 357 //no results
var Backup = require ("@aws-sdk/client-backup"); //update working
var Bedrock = require ("@aws-sdk/client-bedrock"); //update customModelHasTags not working //privateCustomModel works
var CloudFormation = require ("@aws-sdk/client-cloudformation"); //update working //simple works cloudformationAdminPriviliges not SEEMS to be a lot of calls
var CloudFront = require ("@aws-sdk/client-cloudfront"); //update unable to obtain data, status UNKNOWN RESULTS
var CloudTrail = require ("@aws-sdk/client-cloudtrail"); //update working
var CloudWatch = require ("@aws-sdk/client-cloudwatch"); //update working
var CloudWatchLogs = require ("@aws-sdk/client-cloudwatch-logs");// update working
var CodeArtifact = require ("@aws-sdk/client-codeartifact");// update not working
var CodeBuild = require ("@aws-sdk/client-codebuild"); //update unable to obtain data, status UNKNOWN RESULTS
var CodePipeline = require ("@aws-sdk/client-codepipeline");//update working
var CodeStar = require ("@aws-sdk/client-codestar");//update codestarValidRepoProverds creates UNKNOWN RESULTS
var CognitoIdentityServiceProvider = require("@aws-sdk/client-cognito-identity-provider");//update not working
var Comprehend = require("@aws-sdk/client-comprehend") //update worked
var ComputeOptimizer = require("@aws-sdk/client-compute-optimizer") //update UNKNOWN status for compute optimizer
var ConfigService = require("@aws-sdk/client-config-service") //update working
var ClientConnect = require ("@aws-sdk/client-connect"); //update hit call to line 357 KMS List keys
var DevOpsGuru = require ("@aws-sdk/client-devops-guru"); //update UNKNOWN not authorized
var DMS = require ("@aws-sdk/client-database-migration-service"); //update autoMinorVersionUpgrade not working
var DocDB = require ("@aws-sdk/client-docdb"); //update working
var DynamoDB = require ("@aws-sdk/client-dynamodb"); //update working
var EC2 = require('@aws-sdk/client-ec2'); //update UNKNOWN //EC2Client DescribeImagesCommand not workign
var ECR = require ("@aws-sdk/client-ecr"); //updated working
var ECS = require ("@aws-sdk/client-ecs"); //update working
var EFS = require ("@aws-sdk/client-efs"); //update working
var EKS = require ("@aws-sdk/client-eks"); //update some working
var ElastiCache = require ("@aws-sdk/client-elasticache"); //update working
var ElasticBeanstalk = require ("@aws-sdk/client-elastic-beanstalk"); //update working
var ElasticTranscoder = require ("@aws-sdk/client-elastic-transcoder"); //update working
var ELB = require ("@aws-sdk/client-elastic-load-balancing"); // update ELB Not working
var ELBv2 = require ("@aws-sdk/client-elastic-load-balancing-v2"); //update ELBv2 not working
var EMR = require ("@aws-sdk/client-emr"); //update working
var EventBridge = require ("@aws-sdk/client-eventbridge"); //update working
var Finspace = require ("@aws-sdk/client-finspace")//update working
var Firehose = require ("@aws-sdk/client-firehose"); //update working
var ForecastService = require ("@aws-sdk/client-forecast");//update not working
var FraudDetector = require ("@aws-sdk/client-frauddetector");//update working
var FSx = require ("@aws-sdk/client-fsx");//update working
var Glue = require ("@aws-sdk/client-glue");//update workingg
var DataBrew = require ("@aws-sdk/client-databrew");//update working gludedatabrew
var GuardDuty = require ("@aws-sdk/client-guardduty"); //update working
var HealthLake = require ("@aws-sdk/client-healthlake"); //update working
var IAM = require("@aws-sdk/client-iam");//update acessKeysExtra not working
var imagebuilder = require("@aws-sdk/client-imagebuilder");//update not working
var IoTSiteWise = require("@aws-sdk/client-iotsitewise");//update hit 357/call 2 data UNKOWN
var Kendra = require("@aws-sdk/client-kendra");//one working, one UKNOWN
var Kinesis = require ("@aws-sdk/client-kinesis"); //updated working
var KinesisVideo = require ("@aws-sdk/client-kinesis-video");//update working
var KMS = require ("@aws-sdk/client-kms"); //updated hit call 2 /357
var Lambda = require ("@aws-sdk/client-lambda");//update working
var LEX = require ("@aws-sdk/client-lex-models-v2");//update hitting call 357
var Location = require ("@aws-sdk/client-location");//update hitting 357 data UKNOWN
var Lookout = require ("@aws-sdk/client-lookoutvision"); //hit call 1 //update hit 357/call 2
var ManagedBlockChain = require ("@aws-sdk/client-managedblockchain"); //updated hit call 357
var MemoryDB = require ("@aws-sdk/client-memorydb");//updated working
var MQ = require ("@aws-sdk/client-mq");//update not working
var Kafka = require ("@aws-sdk/client-kafka");//updated working MSK
var MWAA = require ("@aws-sdk/client-mwaa"); //updated recursive call never finsishes stuck in 357
var Neptune = require ("@aws-sdk/client-neptune"); //updated works
var OpenSearch = require ("@aws-sdk/client-opensearch"); //updated works
var OpenSearchServerless = require ("@aws-sdk/client-opensearchserverless"); //update hit kms cal 357 and creates data Unknown
var Organizations = require ("@aws-sdk/client-organizations");//update status UNKNOWN
var Proton = require ("@aws-sdk/client-proton"); //update uknown
var QLDB = require ("@aws-sdk/client-qldb");//update worked
//******COMMIT THE NEXT 25 */
var RDS = require ("@aws-sdk/client-rds"); 
//redshift
//route53
var S3 = require ("@aws-sdk/client-s3"); 
//s3glacier
var S3Control = require ("@aws-sdk/client-s3-control"); //not sure what uses this
//sagemaker
//secretsmanager
//securityhub
var SES = require ("@aws-sdk/client-ses"); //uses call 1
//shield
//sns
var SQS = require ("@aws-sdk/client-sqs"); //cross account needs organizations service... sqsEncrypted uses call 1
var SSM = require ("@aws-sdk/client-ssm"); //uses call 1
var STS = require ("@aws-sdk/client-sts"); //not directly run as a plugin
var Support = require ("@aws-sdk/client-support"); //not directly run as a plugin
//timestreamwrite
//transfer
//translate
var WAFRegional = require ("@aws-sdk/client-waf-regional"); //waf:wafInUse called but not finishing
var WAFV2 = require ("@aws-sdk/client-wafv2"); //hit call 1
//workspaces ...uses STS:getCallerIdentity .. not sure where WorkSpaces:describeWorkspacesConnectionStatus is
//xray


const { Agent } = require("https");
const { Agent: HttpAgent } = require("http");
const { NodeHttpHandler } = require("@aws-sdk/node-http-handler");

var rateError = {
    message: 'rate',
    statusCode: 429
};

var apiRetryAttempts = 2;
var apiRetryBackoff = 500;
var apiRetryCap = 1000;

// Loop through all of the top-level collectors for each service
var collect = function(AWSConfig, settings, callback) {
    let apiCallErrors = 0;
    let apiCallTypeErrors = 0;
    let totalApiCallErrors = 0;

    // Used to track rate limiting retries
    let retries = [];

    // Used to gather info only
    if (settings.gather) {
        return callback(null, helpers.calls, helpers.postcalls);
    }

    // Configure an opt-in debug logger
    var AWSXRay;
    var debugMode = settings.debug_mode;
    if (debugMode)
        AWSXRay = require('aws-xray-sdk');
    // Override max sockets
    const customRequestHandler = new NodeHttpHandler({
        agent: new Agent({
            maxSockets: 100
        }),
    });
    AWSConfig.requestHandler = customRequestHandler;
    AWSConfig.maxRetries = 8;
    AWSConfig.retryDelayOptions = {
        base: 100
    };
    
    var regions = helpers.regions(settings);

    var collection = {};
    var errors = {};
    var errorSummary = {};
    var errorTypeSummary = {};

    let runApiCalls = [];

    var AWSEC2 = new EC2.EC2(AWSConfig);

    var params = {
        AllRegions: true
    };
    var excludeRegions = [];

    AWSEC2.describeRegions(params, function(err, accountRegions) {
        if (err) {
            console.log(`[INFO][REGIONS] Could not load all regions from EC2: ${JSON.stringify(err)}`);
        } else {
            if (accountRegions && accountRegions.Regions) {
                excludeRegions = accountRegions.Regions.filter(region=>{
                    return region.OptInStatus == 'not-opted-in';
                }
                );
            }
        }
        console.log(helpers.calls)
        console.log(accountRegions)
        async.eachOfLimit(helpers.calls, 10, function(call, service, serviceCb) {

            var serviceName = service;
            var serviceLower = service.toLowerCase();
            if (!collection[serviceLower])
                collection[serviceLower] = {};

            // Loop through each of the service's functions
            //console.log(call.callObj); Seems to be undefined
            async.eachOfLimit(call, 15, function(callObj, callKey, callCb) {
                console.log(callObj);
                if (settings.api_calls && settings.api_calls.indexOf(serviceName + ':' + callKey) === -1)
                    return callCb();

                runApiCalls.push(serviceName + ':' + callKey);

                if (!collection[serviceLower][callKey]) {
                    collection[serviceLower][callKey] = {};
                    apiCallErrors = 0;
                    apiCallTypeErrors = 0;
                }
                debugMode = true;
                helpers.debugApiCalls(callKey, serviceName, debugMode);
                console.log("helpers")
                var callRegions;

                if (callObj.default) {
                    callRegions = regions.default;
                } else {
                    callRegions = regions[serviceLower];
                }
                console.log(callRegions);
                async.eachLimit(callRegions, helpers.MAX_REGIONS_AT_A_TIME, function(region, regionCb) {

                    if (settings.skip_regions && settings.skip_regions.indexOf(region) > -1 && helpers.globalServices.indexOf(serviceName) === -1)
                        return regionCb();

                    if (excludeRegions && excludeRegions.filter(excluded=>{
                        if (excluded.RegionName == region) {
                            return true;
                        }
                    }
                    ).length) {
                        return regionCb();
                    }

                    if (!collection[serviceLower][callKey][region])
                        collection[serviceLower][callKey][region] = {};

                    var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));
                    LocalAWSConfig.region = region;
                    
                    if (callObj.override) {
                        collectors[serviceLower][callKey](LocalAWSConfig, collection, retries, function() {
                            if (callObj.rateLimit) {
                                setTimeout(function() {
                                    regionCb();
                                }, callObj.rateLimit);
                            } else {
                                regionCb();
                            }
                        });
                    } else {
                        console.log(serviceName)

                        var executor = eval("new "+serviceName+"."+serviceName+"Client({})");
                        //new IAM.IAMClient({});
                        // eval("new "+serviceName+"."+serviceName+"Client({})");
                        executor.middlewareStack.add((next,context)=>async(args)=>{
                            console.log("AWS SDK context", context.clientName, context.commandName);
                            console.log("AWS SDK request input", args.input);
                            const result = await next(args);
                            console.log("AWS SDK request output:", result.output);
                            return result;
                        }
                        , {
                            name: "MyMiddleware",
                            step: "build",
                            override: true,
                        });

                        var paginating = false;
                        console.log(LocalAWSConfig.region)
                        console.log("made it through callback")
                        //not making it through  call back
                        var executorCb = function(err, data) {
                            if (err) {
                                collection[serviceLower][callKey][region].err = err;
                                debugMode = false
                                console.log("EEERRRRRR");
                                helpers.logError(serviceLower, callKey, region, err, errors, apiCallErrors, apiCallTypeErrors, totalApiCallErrors, errorSummary, errorTypeSummary, debugMode);
                            }
                            console.log("made it to execCB");
                            if (!data)
                                return regionCb();
                            if (callObj.property && !data[callObj.property])
                                return regionCb();
                            if (callObj.secondProperty && !data[callObj.secondProperty])
                                return regionCb();

                            var dataToAdd = callObj.secondProperty ? data[callObj.property][callObj.secondProperty] : data[callObj.property] ? data[callObj.property] : data;

                            if (paginating) {
                                collection[serviceLower][callKey][region].data = collection[serviceLower][callKey][region].data.concat(dataToAdd);
                            } else {
                                collection[serviceLower][callKey][region].data = dataToAdd;
                            }

                            // If a "paginate" property is set, e.g. NextToken
                            var nextToken = callObj.paginate;
                            if (settings.paginate && nextToken && data[nextToken]) {
                                paginating = true;
                                var paginateProp = callObj.paginateReqProp ? callObj.paginateReqProp : nextToken;
                                return execute([paginateProp, data[nextToken]]);
                            }
                            console.log("CALLING REGIONCB");
                            regionCb();
                        };

                        function execute(nextTokens) {
                            // eslint-disable-line no-inner-declarations
                            // Each region needs its own local copy of callObj.params
                            // so that the injection of the NextToken doesn't break other calls
                            console.log("IN EXECUTE");
                            var localParams = JSON.parse(JSON.stringify(callObj.params || {}));
                            console.log(localParams);
                            if (nextTokens)
                                localParams[nextTokens[0]] = nextTokens[1];
                            if (callObj.params || nextTokens) {
                                async.retry({
                                    times: apiRetryAttempts,
                                    interval: function(retryCount) {
                                        let retryExponential = 3;
                                        let retryLeveler = 3;
                                        let timestamp = parseInt(((new Date()).getTime()).toString().slice(-1));
                                        let retry_temp = Math.min(apiRetryCap, (apiRetryBackoff * (retryExponential + timestamp) ** retryCount));
                                        let retry_seconds = Math.round(retry_temp / retryLeveler + Math.random(0, retry_temp) * 5000);

                                        console.log(`Trying ${callKey} again in: ${retry_seconds / 1000} seconds`);
                                        retries.push({
                                            seconds: Math.round(retry_seconds / 1000)
                                        });
                                        return retry_seconds;
                                    },
                                    errorFilter: function(err) {
                                        console.log(err);
                                        return helpers.collectRateError(err, rateError);
                                    }
                                }, function(cb) {
                                    console.log("call 349");
                                    className = callKey[0].toUpperCase()+callKey.slice(1);
                                   console.log("new "+serviceName+"."+className+"Command();")
                                    executor.send(eval("new "+serviceName+"."+className+"Command();"),function(err, data) {
                                        return cb(err, data);
                                  });
                                }, function(err, data) {
                                    console.log("call 357");
                                    executorCb(err, data);
                                });
                            } else {
                                async.retry({
                                    times: apiRetryAttempts,
                                    interval: function(retryCount) {
                                        let retryExponential = 3;
                                        let retryLeveler = 3;
                                        let timestamp = parseInt(((new Date()).getTime()).toString().slice(-1));
                                        let retry_temp = Math.min(apiRetryCap, (apiRetryBackoff * (retryExponential + timestamp) ** retryCount));
                                        let retry_seconds = Math.round(retry_temp / retryLeveler + Math.random(0, retry_temp) * 5000);

                                        console.log(`Trying ${callKey} again in: ${retry_seconds / 1000} seconds`);
                                        retries.push({
                                            seconds: Math.round(retry_seconds / 1000)
                                        });
                                        return retry_seconds;
                                    },
                                    errorFilter: function(err) {
                                        return helpers.collectRateError(err, rateError);
                                    }
                                }, function(cb) {
                                    console.log("call 248");
                                    
                                  className = callKey[0].toUpperCase()+callKey.slice(1);
                                  console.log("new "+serviceName+"."+className+"Command();")
                                  executor.send(eval("new "+serviceName+"."+className+"Command();"),function(err, data) {
                                        return cb(err, data);
                                  });
                                 
                                    
                                }, function(err, data) {
                                    console.log("call 254");
                                    executorCb(err, data);
                                });
                                
                            }
                        }
                        console.log("line 279");
                        execute();
                    }
                }, function() {
                    debugMode = true;
                    helpers.debugApiCalls(callKey, serviceName, debugMode);
                    callCb();
                });
            }, function() {
                return serviceCb();
            });
        }, function() {
            // Now loop through the follow up calls
            console.log("IN FOLLOW UP CALLS");
            async.eachSeries(helpers.postcalls, function(postcallObj, postcallCb) {
                async.eachOfLimit(postcallObj, 10, function(serviceObj, service, serviceCb) {
                    var serviceName = service;
                    var serviceLower = service.toLowerCase();
                    var serviceIntegration = {
                        enabled: postcallObj && postcallObj[serviceName] && postcallObj[serviceName].sendIntegration && postcallObj[serviceName].sendIntegration.enabled ? true : false,
                        sendLast: postcallObj && postcallObj[serviceName] && postcallObj[serviceName].sendIntegration && postcallObj[serviceName].sendIntegration.sendLast ? true : false
                    };

                    if (!collection[serviceLower])
                        collection[serviceLower] = {};

                    async.eachOfLimit(serviceObj, 1, function(callObj, callKey, callCb) {
                        if (settings.api_calls && settings.api_calls.indexOf(serviceName + ':' + callKey) === -1)
                            return callCb();

                        runApiCalls.push(serviceName + ':' + callKey);

                        if (!collection[serviceLower][callKey]) {
                            collection[serviceLower][callKey] = {};
                            apiCallErrors = 0;
                            apiCallTypeErrors = 0;
                        }
                        debugMode = false;
                        helpers.debugApiCalls(callKey, serviceName, debugMode);

                        async.eachLimit(regions[serviceLower], helpers.MAX_REGIONS_AT_A_TIME, function(region, regionCb) {
                            if (settings.skip_regions && settings.skip_regions.indexOf(region) > -1 && helpers.globalServices.indexOf(serviceName) === -1)
                                return regionCb();

                            if (excludeRegions && excludeRegions.filter(excluded=>{
                                if (excluded.RegionName == region) {
                                    return true;
                                }
                            }
                            ).length) {
                                return regionCb();
                            }

                            if (!collection[serviceLower][callKey][region])
                                collection[serviceLower][callKey][region] = {};

                            // Ensure pre-requisites are met
                            if (callObj.reliesOnService && !collection[callObj.reliesOnService])
                                return regionCb();

                            if (callObj.reliesOnCall && (!collection[callObj.reliesOnService] || !collection[callObj.reliesOnService][callObj.reliesOnCall] || !collection[callObj.reliesOnService][callObj.reliesOnCall][region] || !collection[callObj.reliesOnService][callObj.reliesOnCall][region].data || !collection[callObj.reliesOnService][callObj.reliesOnCall][region].data.length))
                                return regionCb();

                            var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));
                            if (callObj.deleteRegion) {
                                //delete LocalAWSConfig.region;
                                LocalAWSConfig.region = settings.govcloud ? 'us-gov-west-1' : settings.china ? 'cn-north-1' : 'us-east-1';
                            } else {
                                LocalAWSConfig.region = region;
                            }
                            if (callObj.signatureVersion)
                                LocalAWSConfig.signatureVersion = callObj.signatureVersion;

                            if (callObj.override) {
                                collectors[serviceLower][callKey](LocalAWSConfig, collection, retries, function() {

                                    if (callObj.rateLimit) {
                                        setTimeout(function() {
                                            regionCb();
                                        }, callObj.rateLimit);
                                    } else {
                                        regionCb();
                                    }
                                });
                            } else {
                                var executor = eval("new "+serviceName+"."+serviceName+"Client({})");
                                //AWS[serviceName](LocalAWSConfig);

                                if (!collection[callObj.reliesOnService][callObj.reliesOnCall][LocalAWSConfig.region] || !collection[callObj.reliesOnService][callObj.reliesOnCall][LocalAWSConfig.region].data) {
                                    return regionCb();
                                }

                                async.eachLimit(collection[callObj.reliesOnService][callObj.reliesOnCall][LocalAWSConfig.region].data, 10, function(dep, depCb) {
                                    collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]] = {};

                                    var filter = {};
                                    filter[callObj.filterKey] = dep[callObj.filterValue];

                                    async.retry({
                                        times: apiRetryAttempts,
                                        interval: function(retryCount) {
                                            let retryExponential = 3;
                                            let retryLeveler = 3;
                                            let timestamp = parseInt(((new Date()).getTime()).toString().slice(-1));
                                            let retry_temp = Math.min(apiRetryCap, (apiRetryBackoff * (retryExponential + timestamp) ** retryCount));
                                            let retry_seconds = Math.round(retry_temp / retryLeveler + Math.random(0, retry_temp) * 5000);

                                            console.log(`Trying ${callKey} again in: ${retry_seconds / 1000} seconds`);
                                            retries.push({
                                                seconds: Math.round(retry_seconds / 1000)
                                            });
                                            return retry_seconds;
                                        },
                                        errorFilter: function(err) {
                                            return helpers.collectRateError(err, rateError);
                                        }
                                    }, function(cb) {
                                        console.log("call 410");

                                        className = callKey[0].toUpperCase()+callKey.slice(1);
                                        command = eval("new "+serviceName+"."+className+"Command();");
                                        command.input=filter;
                                        executor.send(command,function(err, data) {

                                        if (helpers.collectRateError(err, rateError)) {
                                            return cb(err);
                                        } else if (err) {
                                            collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]].err = err;
                                            helpers.logError(serviceLower, callKey, region, err, errors, apiCallErrors, apiCallTypeErrors, totalApiCallErrors, errorSummary, errorTypeSummary, debugMode);
                                            return cb();
                                        } else {
                                            collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]].data = data;
                                            return cb();
                                        }
                                        });
                                    }, function() {

                                        if (callObj.rateLimit) {
                                            setTimeout(function() {
                                                depCb();
                                            }, callObj.rateLimit);
                                        } else {
                                            depCb();
                                        }
                                    });
                                }, function() {
                                    regionCb();
                                });
                            }
                        }, function() {
                            helpers.debugApiCalls(callKey, serviceName, debugMode);
                            callCb();
                        });
                    }, function() {
                        if (serviceIntegration.enabled && !serviceIntegration.sendLast && settings.identifier && collection[serviceLower] && Object.keys(collection[serviceLower]) && Object.keys(collection[serviceLower]).length && collectData.callsCollected(serviceName, collection, helpers.calls, helpers.postcalls)) {
                            try {
                                collectData.processIntegration(serviceName, settings, collection, helpers.calls, helpers.postcalls, debugMode, function() {
                                    return serviceCb();
                                });
                            } catch (e) {
                                return serviceCb();
                            }
                        } else {
                            return serviceCb();
                        }
                    });
                }, function() {
                    postcallCb();
                });
            }, function() {
                if (settings.identifier) {
                    async.each(helpers.integrationSendLast, function(serv, cb) {
                        settings.identifier.service = serv.toLowerCase();

                        if (collection[serv.toLowerCase()] && Object.keys(collection[serv.toLowerCase()]) && Object.keys(collection[serv.toLowerCase()]).length && collectData.callsCollected(serv, collection, helpers.calls, helpers.postcalls)) {
                            try {
                                collectData.processIntegration(serv, settings, collection, helpers.calls, helpers.postcalls, debugMode, function() {
                                    console.log(`Integration for service ${serv} processed.`);
                                    cb();
                                });
                            } catch (e) {
                                cb();
                            }

                        } else {
                            cb();
                        }
                    }, function() {
                        console.log("call 449");
                        callback(null, collection, runApiCalls, errorSummary, errorTypeSummary, errors, retries);
                    });

                } else {
                    console.log("call 454");
                    callback(null, collection, runApiCalls, errorSummary, errorTypeSummary, errors, retries);

                }

            });
        });
    });
};

module.exports = collect;
