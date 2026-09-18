import * as pulumi from "@pulumi/pulumi";
import {mock} from "node:test";
import childProcess from "node:child_process";
import {deployAWS} from "../src/aws";
import {deployGCP} from "../src/gcp";
import {deployAzure} from "../src/azure";
import {Cloud, Settings} from "../src/settings";

function plain(value: any): any {
    if (value && typeof value === "object") {
        if (value["4dabf18193072939515e22adb298388d"] === "1b47061264138c4ac30d75fd1eb44270") return plain(value.value);
        if (Array.isArray(value)) return value.map(plain);
        return Object.fromEntries(Object.entries(value).map(([key, v]) => [key, plain(v)]));
    }
    return value;
}
const resources: {type: string; name: string; inputs: any}[] = [];
mock.method(childProcess, "execFileSync", (command: string, args: string[]) => {
    if (command !== "az" || args[0] !== "acr" || !args.includes("--expose-token")) throw new Error("Unexpected external command");
    if (args[args.indexOf("--subscription") + 1] !== "subscription-id") throw new Error("Wrong Azure subscription");
    return JSON.stringify({accessToken: "test-token"});
});
pulumi.runtime.setMocks({
    newResource(args) {
        resources.push({type: args.type, name: args.name, inputs: plain(args.inputs)});
        const state = {...plain(args.inputs), name: args.inputs.name ?? args.name, arn: `arn:test:${args.name}`};
        if (args.type === "aws:lambda/functionUrl:FunctionUrl") state.functionUrl = "https://aws.example/";
        if (args.type === "gcp:serviceaccount/account:Account") state.email = "runtime@project.iam.gserviceaccount.com";
        if (args.type === "gcp:cloudrunv2/service:Service") state.uri = "https://gcp.example";
        if (args.type === "docker:index/image:Image") state.repoDigest = "registry.example/receiver@sha256:1234";
        if (args.type === "azure-native:containerregistry:Registry") state.loginServer = "registry.example";
        if (args.type === "azure-native:managedidentity:UserAssignedIdentity") state.principalId = "principal-id";
        if (args.type === "azure-native:operationalinsights:Workspace") state.customerId = "customer-id";
        if (args.type === "azure-native:app:ContainerApp") state.configuration.ingress.fqdn = "azure.example";
        return {id: `${args.name}-id`, state};
    },
    call(args) {
        if (args.token.includes("getClientConfig")) return {accessToken: "test-token", subscriptionId: "subscription-id"};
        if (args.token.includes("getWorkspaceSharedKeys")) return {primarySharedKey: "test-key"};
        return args.inputs;
    },
}, "honeylambda", "Mixed.Case-Stack", false);

const cloud = process.argv[2] as Cloud;
const settings: Settings = {cloud, region: "test-region", maxInstances: 3, configFile: "unused", projectId: "project-id"};
const pkg = {directory: ".", service: {alerts: {}, tokens: []}};
(async () => {
    await pulumi.runtime.runInPulumiStack(async () => {
        const result = {aws: deployAWS, gcp: deployGCP, azure: deployAzure}[cloud](settings, pkg, {MY_NOTIFICATION: pulumi.secret(process.argv[3] ?? "https://notifications.example/"), HONEY_REMOTE_CONFIG_URL: pulumi.secret("https://config.example/config.json"), HONEY_REMOTE_REFRESH_SECONDS: "60", HONEY_REMOTE_TIMEOUT_MS: "2000"});
        return {endpoint: result.endpoint, logs: result.logs};
    });
    process.stdout.write(JSON.stringify(resources));
})();
