// SPDX-License-Identifier: GPL-3.0-or-later
import * as gcp from "@pulumi/gcp";
import * as pulumi from "@pulumi/pulumi";
import {Settings, resourceName} from "./settings";
import {Package} from "./package";
import {image} from "./image";

export function deployGCP(s: Settings, pkg: Package, environment: Record<string, pulumi.Input<string>>) {
    const provider = new gcp.Provider("gcp", {project: s.projectId!, region: s.region});
    const opts = {provider};
    const services = ["run.googleapis.com", "artifactregistry.googleapis.com", "iam.googleapis.com"].map(service => new gcp.projects.Service(service.split(".")[0], {
        project: s.projectId!, service, disableOnDestroy: false,
    }, opts));
    const repository = new gcp.artifactregistry.Repository("receiver", {
        location: s.region, format: "DOCKER", repositoryId: resourceName(),
        // Keep images for rollback; cleanup cannot determine which digests are still serving.
    }, {...opts, dependsOn: services});
    const auth = gcp.organizations.getClientConfigOutput(opts);
    const registry = `${s.region}-docker.pkg.dev`;
    const built = image(pkg, pulumi.interpolate`${registry}/${s.projectId}/${repository.repositoryId}/receiver:current`, {
        server: registry, username: "oauth2accesstoken", password: pulumi.secret(auth.accessToken),
    });
    const account = new gcp.serviceaccount.Account("receiver", {accountId: resourceName(), displayName: "honeyLambda runtime"}, {...opts, dependsOn: services});
    const receiver = new gcp.cloudrunv2.Service("receiver", {
        location: s.region, deletionProtection: false, ingress: "INGRESS_TRAFFIC_ALL",
        template: {
            executionEnvironment: "EXECUTION_ENVIRONMENT_GEN2", serviceAccount: account.email, timeout: "30s", maxInstanceRequestConcurrency: 20,
            scaling: {minInstanceCount: 0, maxInstanceCount: s.maxInstances},
            containers: [{
                image: built.repoDigest, ports: {containerPort: 8080},
                resources: {limits: {cpu: "1", memory: "512Mi"}, cpuIdle: true},
                envs: Object.entries(environment).map(([name, value]) => ({name, value})),
                startupProbe: {tcpSocket: {port: 8080}},
            }],
        },
    }, {...opts, dependsOn: services});
    const access = new gcp.cloudrunv2.ServiceIamMember("public", {
        project: s.projectId!, location: s.region, name: receiver.name, role: "roles/run.invoker", member: "allUsers",
    }, opts);
    return {endpoint: pulumi.all([receiver.uri, access.id]).apply(([endpoint]) => endpoint), logs: receiver.name};
}
