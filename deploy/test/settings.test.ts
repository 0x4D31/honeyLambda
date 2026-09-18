import {test} from "node:test";
import assert from "node:assert/strict";
import * as pulumi from "@pulumi/pulumi";
import {settings, tokenURLs, notificationEnvironment} from "../src/settings";

function config(values: Record<string, string>) {
    pulumi.runtime.setAllConfig(Object.fromEntries(Object.entries(values).map(([k, v]) => [`honeylambda:${k}`, v])));
    return new pulumi.Config("honeylambda");
}

test("deployment settings reject invalid cloud, region, capacity and missing project", () => {
    for (const bad of ([{cloud: "typo"}, {maxInstances: "0"}, {maxInstances: "1.5"}, {region: "East US"}, {cloud: "gcp"}] as Record<string, string>[])) {
        assert.throws(() => settings(config({cloud: "aws", region: "us-east-1", ...bad})));
    }
    const valid = settings(config({cloud: "azure", region: "eastus"}));
    assert.equal(valid.maxInstances, 2);
    assert.equal(valid.projectId, undefined);
    assert.equal(settings(config({cloud: "aws", region: "us-east-1"})).maxInstances, undefined);
});

test("notification settings fail early when missing or unused", () => {
    assert.throws(() => notificationEnvironment({alerts: {webhook_url_env: "CUSTOM_URL"}, tokens: []}, config({})), /Set webhookURL/);
    assert.throws(() => notificationEnvironment({alerts: {}, tokens: []}, config({webhookURL: "https://example.org"})), /not enabled/);
});

test("token URLs preserve escaped paths and encode all query parameters", () => {
    assert.deepEqual(tokenURLs("https://receiver.example/", {alerts: {}, tokens: [{id: "doc", path: "/a/../%2F", query: {z: "a b", a: "&="}}]}), {doc: "https://receiver.example/a/../%2F?a=%26%3D&z=a+b"});
});

test("remote settings are explicit, bounded and mapped to all runtime names", async () => {
    const {runtimeEnvironment} = await import("../src/settings");
    const service = {alerts: {}, tokens: []};
    assert.throws(() => runtimeEnvironment(service, config({configRefreshSeconds: "60"})), /require configURL/);
    assert.throws(() => runtimeEnvironment(service, config({configURL: "https://example.org/config.json", configTimeoutMS: "9000"})), /between/);
    const environment = runtimeEnvironment(service, config({configURL: "https://example.org/config.json", configToken: "example-token"}));
    const resolved = await new Promise<Record<string, string>>(resolve => pulumi.output(environment).apply(value => { resolve(value); return value; }));
    assert.deepEqual(resolved, {
        HONEY_REMOTE_CONFIG_URL: "https://example.org/config.json", HONEY_REMOTE_CONFIG_TOKEN: "example-token",
        HONEY_REMOTE_REFRESH_SECONDS: "60", HONEY_REMOTE_TIMEOUT_MS: "2000",
    });
});
