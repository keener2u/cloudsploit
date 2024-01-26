const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Application Gateway Request Body Size',
    category: 'Application Gateway',
    domain: 'Network Access Control',
    description: 'Ensures that Application Gateway WAF policy have desired request body size configured.',
    more_info: 'Application Gateway WAF policy includes a maximum request body size field, specified in kilobytes. This setting controls the overall request size limit, excluding any file uploads. Configuring an appropriate value for this field is crucial for optimizing security and performance.',
    recommended_action: 'Modify application gateway WAF policy, enable request body inspection and set the desired request body size.',
    link: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits',
    apis: ['wafPolicies:listAll'],
    settings: {
        max_request_body_size: {
            name: 'Max request body size',
            description: 'The default value for request body size is 128.',
            regex: '^(12[8-9]|1[3-9]{1,2}|2000)$',
            default: '128',
        },
    },
    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        var config = {
            max_request_body_size: settings.max_request_body_size || this.settings.max_request_body_size.default,
        };

        async.each(locations.wafPolicies, (location, rcb) => {

            var wafPolicies = helpers.addSource(cache, source,
                ['wafPolicies', 'listAll', location]);

            if (!wafPolicies) return rcb();

            if (wafPolicies.err || !wafPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query for Application Gateway WAF policies: ' + helpers.addError(wafPolicies), location);
                return rcb();
            }
            if (!wafPolicies.data.length) {
                helpers.addResult(results, 0, 'No existing WAF policies found', location);
                return rcb();
            }

            for (let policy of wafPolicies.data) {
                if (!policy.id) continue;
                var maxRequestBodySize = config.max_request_body_size;
                var bodyInspection = policy.policySettings && policy.policySettings.requestBodyCheck ? policy.policySettings.requestBodyCheck : false;
                if (bodyInspection) {
                    if (policy.policySettings && policy.policySettings.maxRequestBodySizeInKb && policy.policySettings.maxRequestBodySizeInKb >= maxRequestBodySize) {
                        helpers.addResult(results, 0, `Application gateway WAF policy has max request body size of ${maxRequestBodySize}`, location, policy.id);
                    } else {
                        helpers.addResult(results, 2, `Application gateway WAF policy has max request body size of ${policy.policySettings.maxRequestBodySizeInKb} which is less than ${maxRequestBodySize}`, location, policy.id);
                    }
                } else {
                    helpers.addResult(results, 0, 'Request Body Inspection is not enabled for WAF policy', location, policy.id);
                }

            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
