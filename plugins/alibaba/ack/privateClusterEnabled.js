var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Private ClusterEnabled',
    category: 'ACK',
    domain: 'Containers',
    description: 'Ensure Kubernetes Cluster is created with Private cluster enabled.',
    more_info: 'A private cluster in Alibaba Cloud Container Service for Kubernetes (ACK) restricts access to the Kubernetes API server from the public internet, making it more secure. In a private cluster, the API Server Public Network Endpoint is not exposed to the internet. This reduces the risk of unauthorized access and helps protect sensitive data and workloads. It is recommended to have Private Cluster enabled for better security.',
    link: 'https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/control-public-access-to-the-api-server-of-a-cluster',
    recommended_action: 'Recreate Kubernetes clusters and make sure Public Access is not enabled.',
    apis: ['ACK:describeClustersV1', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var defaultRegion = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', defaultRegion, 'data']);

        var describeClusters = helpers.addSource(cache, source, ['ack', 'describeClustersV1', defaultRegion]);

        if (!describeClusters) return callback(null, results, source);

        if (describeClusters.err || !describeClusters.data) {
            helpers.addResult(results, 3, `Unable to query ACK clusters: ${helpers.addError(describeClusters)}`, defaultRegion);
            return callback(null, results, source);
        }

        if (!describeClusters.data.length) {
            helpers.addResult(results, 0, 'No ACK clusters found', defaultRegion);
            return callback(null, results, source);
        }

        describeClusters.data.forEach(cluster => {
            if (!cluster.cluster_id) return;

            var resource = helpers.createArn('cs', accountId, 'cluster', cluster.cluster_id, defaultRegion);
 
            if (cluster.master_url) {
                var masterUrl = JSON.parse(cluster.master_url);
                if (masterUrl.api_server_endpoint && masterUrl.api_server_endpoint !== '') {
                    helpers.addResult(results, 2, 'Cluster does not have Private Cluster enabled', defaultRegion, resource);
                } else {
                    helpers.addResult(results, 0, 'Cluster has Private Cluster enabled', defaultRegion, resource);
                }
            } else {
                helpers.addResult(results, 3, `Could not find master_url info for cluster ${cluster.cluster_id}`, defaultRegion, resource);
            }
        });

        callback(null, results, source);
    }
};
