// SPDX-License-Identifier: GPL-3.0-or-later
import * as azure from "@pulumi/azure-native";
import * as pulumi from "@pulumi/pulumi";
import {createHash} from "node:crypto";
import {execFileSync} from "node:child_process";
import {Settings, environmentRevision} from "./settings";
import {Package} from "./package";
import {image} from "./image";

export function deployAzure(s: Settings, pkg: Package, environment: Record<string, pulumi.Input<string>>) {
    const provider = new azure.Provider("azure", {location: s.region});
    const opts = {provider};
    const group = new azure.resources.ResourceGroup("receiver", {}, opts);
    const common = {resourceGroupName: group.name, location: s.region};
    const workspace = new azure.operationalinsights.Workspace("receiver", {
        ...common, retentionInDays: 30, sku: {name: "PerGB2018"},
    }, opts);
    const workspaceKeys = azure.operationalinsights.getWorkspaceSharedKeysOutput({resourceGroupName: group.name, workspaceName: workspace.name}, opts);
    const platform = new azure.app.ManagedEnvironment("receiver", {
        ...common,
        appLogsConfiguration: {destination: "log-analytics", logAnalyticsConfiguration: {customerId: workspace.customerId, sharedKey: pulumi.secret(workspaceKeys.primarySharedKey).apply(key => key!)}},
    }, opts);
    const registry = new azure.containerregistry.Registry("receiver", {...common, sku: {name: "Basic"}, adminUserEnabled: false, policies: {azureADAuthenticationAsArmPolicy: {status: "enabled"}}}, opts);
    // Use the deployer's short-lived Azure CLI credential only for the image push.
    const client = azure.authorization.getClientConfigOutput(opts);
    const password = pulumi.secret(pulumi.all([registry.name, client.subscriptionId]).apply(([name, subscription]) => {
        const result = JSON.parse(execFileSync("az", ["acr", "login", "--name", name, "--subscription", subscription, "--expose-token", "--output", "json"], {timeout: 30000, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"]}));
        if (!result.accessToken) throw new Error("Azure CLI did not return an ACR access token");
        return result.accessToken as string;
    }));
    const identity = new azure.managedidentity.UserAssignedIdentity("receiver", common, opts);
    const pull = new azure.authorization.RoleAssignment("receiver-pull", {
        scope: registry.id, principalId: identity.principalId, principalType: "ServicePrincipal",
        roleDefinitionId: pulumi.interpolate`/subscriptions/${client.subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/7f951dda-4ed3-4680-a7ca-43fe172d538d`,
    }, opts);
    const built = image(pkg, pulumi.interpolate`${registry.loginServer}/receiver:current`, {
        server: registry.loginServer, username: "00000000-0000-0000-0000-000000000000", password,
    });
    const secrets = Object.entries(environment).map(([name, value]) => ({name: `setting-${createHash("sha256").update(name).digest("hex").slice(0, 16)}`, value, env: name}));
    const receiver = new azure.app.ContainerApp("receiver", {
        ...common, managedEnvironmentId: platform.id,
        identity: {type: "UserAssigned", userAssignedIdentities: [identity.id]},
        configuration: {
            activeRevisionsMode: "Single",
            ingress: {external: true, targetPort: 8080, transport: "http", allowInsecure: false},
            registries: [{server: registry.loginServer, identity: identity.id}],
            secrets: secrets.map(({name, value}) => ({name, value})),
        },
        template: {
            containers: [{name: "receiver", image: built.repoDigest,
                resources: {cpu: 0.25, memory: "0.5Gi"},
                env: [...secrets.map(({env, name}) => ({name: env, secretRef: name})),
                    {name: "HONEY_DEPLOYMENT_REVISION", value: pulumi.output(environment).apply(environmentRevision)}],
                probes: [{type: "Startup", tcpSocket: {port: 8080}, periodSeconds: 1, failureThreshold: 30}],
            }],
            scale: {minReplicas: 0, maxReplicas: s.maxInstances, rules: [{name: "http", http: {metadata: {concurrentRequests: "20"}}}]},
        },
    }, {...opts, dependsOn: [pull]});
    return {endpoint: receiver.configuration.apply(config => `https://${config!.ingress!.fqdn}`), logs: workspace.name};
}
