// SPDX-License-Identifier: GPL-3.0-or-later
import * as pulumi from "@pulumi/pulumi";
import * as path from "node:path";
import {createHash} from "node:crypto";

export type Cloud = "aws" | "gcp" | "azure";
export interface Settings {
    cloud: Cloud;
    region: string;
    configFile: string;
    maxInstances?: number;
    projectId?: string;
}

export function settings(config = new pulumi.Config()): Settings {
    const cloud = config.require("cloud");
    if (cloud !== "aws" && cloud !== "gcp" && cloud !== "azure") {
        throw new Error("cloud must be aws, gcp, or azure");
    }
    const region = config.require("region");
    if (!/^[a-z][a-z0-9-]+$/.test(region)) throw new Error("region must be a cloud region identifier");
    const maxInstances = config.getNumber("maxInstances") ?? (cloud === "aws" ? undefined : 2);
    if (maxInstances !== undefined && (!Number.isInteger(maxInstances) || maxInstances < 1 || maxInstances > 100)) {
        throw new Error("maxInstances must be an integer between 1 and 100");
    }
    return {
        cloud, region, maxInstances,
        configFile: path.resolve(config.get("configFile") ?? "../config.json"),
        projectId: cloud === "gcp" ? config.require("projectId") : undefined,
    };
}

export interface ServiceConfig {
    alerts: {slack_url_env?: string; webhook_url_env?: string};
    tokens: {id: string; path: string; query?: Record<string, string>}[];
}

export function notificationEnvironment(service: ServiceConfig, config = new pulumi.Config()): Record<string, pulumi.Input<string>> {
    const result: Record<string, pulumi.Input<string>> = {};
    for (const [key, name] of [
        ["slackWebhook", service.alerts.slack_url_env],
        ["webhookURL", service.alerts.webhook_url_env],
    ]) {
        const value = config.getSecret(key!);
        if (name) {
            if (!value) throw new Error(`Set ${key} with pulumi config set --secret; service config enables ${name}`);
            if (name in result) throw new Error("Notification destinations must use distinct environment variable names");
            result[name] = value.apply(url => {
                const parsed = new URL(url);
                if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash) {
                    throw new Error(`${key} must be an HTTPS URL without user information or fragment`);
                }
                return url;
            });
        } else if (value) {
            throw new Error(`${key} is set but its notification destination is not enabled in the service config`);
        }
    }
    return result;
}

// Preserve escaped paths (including dot segments); URL resolution would normalize them.
export function tokenURLs(endpoint: string, service: ServiceConfig): Record<string, string> {
    return Object.fromEntries(service.tokens.map(t => {
        const query = new URLSearchParams(Object.entries(t.query ?? {}).sort()).toString();
        return [t.id, endpoint.replace(/\/$/, "") + t.path + (query ? `?${query}` : "")];
    }));
}

// Stable, bounded names valid even when the Pulumi stack has dots or uppercase.
export function resourceName(): string {
    return "honeylambda-" + createHash("sha256").update(pulumi.getProject() + "\0" + pulumi.getStack()).digest("hex").slice(0, 12);
}
