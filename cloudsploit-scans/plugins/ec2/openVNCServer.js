var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Open VNC Server',
	category: 'EC2',
	description: 'Determine if TCP port 5900 for VNC Server is open to the public',
	more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as VNC Server should be restricted to known IP addresses.',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
	recommended_action: 'Restrict TCP port 5900 to known IP addresses',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		async.eachLimit(helpers.regions.ec2, helpers.MAX_REGIONS_AT_A_TIME, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var ec2 = new AWS.EC2(LocalAWSConfig);

			// Get the account attributes
			helpers.cache(cache, ec2, 'describeSecurityGroups', function(err, data) {
				if (err || !data || !data.SecurityGroups) {
					results.push({
						status: 3,
						message: 'Unable to query for security groups',
						region: region
					});

					return rcb();
				}

				if (!data.SecurityGroups.length) {
					results.push({
						status: 0,
						message: 'No security groups present',
						region: region
					});

					return rcb();
				}

				for (i in data.SecurityGroups) {
					for (j in data.SecurityGroups[i].IpPermissions) {
						var permission = data.SecurityGroups[i].IpPermissions[j];

						for (k in permission.IpRanges) {
							var range = permission.IpRanges[k];

							if (range.CidrIp === '0.0.0.0/0') {
								if (permission.IpProtocol === 'tcp' && permission.FromPort <= 5900 && permission.ToPort >= 5900) {
									results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has VNC Server TCP port 5900 open to 0.0.0.0/0',
										region: region,
										resource: data.SecurityGroups[i].GroupId
									});
								}
							}
						}
					}
				}

				if (!results.length) {
					results.push({
						status: 0,
						message: 'No public open ports found',
						region: region
					});
				}

				rcb();
			});
		}, function(){
			callback(null, results);
		});
	}
};
