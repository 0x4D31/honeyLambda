// SPDX-License-Identifier: GPL-3.0-or-later
import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import {Settings, resourceName} from "./settings";
import {Package} from "./package";

export function deployAWS(s: Settings, pkg: Package, environment: Record<string, pulumi.Input<string>>) {
    const provider = new aws.Provider("aws", {region: s.region as aws.Region});
    const opts = {provider};
    const role = new aws.iam.Role("receiver", {
        assumeRolePolicy: JSON.stringify({Version: "2012-10-17", Statement: [{Effect: "Allow", Principal: {Service: "lambda.amazonaws.com"}, Action: "sts:AssumeRole"}]}),
    }, opts);
    // Explicit shared name avoids a function -> log group -> policy -> function cycle.
    const name = resourceName();
    const logs = new aws.cloudwatch.LogGroup("receiver", {name: `/aws/lambda/${name}`, retentionInDays: 14}, opts);
    const policy = new aws.iam.RolePolicy("receiver-logs", {
        role: role.id,
        policy: logs.arn.apply(arn => JSON.stringify({Version: "2012-10-17", Statement: [{Effect: "Allow", Action: ["logs:CreateLogStream", "logs:PutLogEvents"], Resource: `${arn}:*`}]})),
    }, opts);
    const receiver = new aws.lambda.Function("receiver", {
        name, role: role.arn, runtime: "provided.al2023", handler: "bootstrap",
        architectures: ["arm64"], memorySize: 128, timeout: 20,
        reservedConcurrentExecutions: s.maxInstances ?? -1,
        code: new pulumi.asset.FileArchive(pkg.directory),
        environment: {variables: {HONEY_CONFIG: "config/config.json", ...environment}},
    }, {...opts, dependsOn: [policy]});
    const url = new aws.lambda.FunctionUrl("receiver", {functionName: receiver.name, authorizationType: "NONE", invokeMode: "BUFFERED"}, opts);
    const permissions = [
        new aws.lambda.Permission("public-url", {function: receiver.name, action: "lambda:InvokeFunctionUrl", principal: "*", functionUrlAuthType: "NONE"}, opts),
        new aws.lambda.Permission("public-invocation", {function: receiver.name, action: "lambda:InvokeFunction", principal: "*", invokedViaFunctionUrl: true}, opts),
    ];
    return {endpoint: pulumi.all([url.functionUrl, ...permissions.map(p => p.id)]).apply(([endpoint]) => endpoint), logs: logs.name};
}
