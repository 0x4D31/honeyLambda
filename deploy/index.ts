// SPDX-License-Identifier: GPL-3.0-or-later
import * as pulumi from "@pulumi/pulumi";
import {settings, runtimeEnvironment, tokenURLs as urls} from "./src/settings";
import {prepare} from "./src/package";
import {deployAWS} from "./src/aws";
import {deployGCP} from "./src/gcp";
import {deployAzure} from "./src/azure";

const config = settings();
const pkg = prepare(config, pulumi.getStack());
const environment = runtimeEnvironment(pkg.service);
const result = {aws: deployAWS, gcp: deployGCP, azure: deployAzure}[config.cloud](config, pkg, environment);
export const cloud = config.cloud;
export const endpoint = result.endpoint;
export const logs = result.logs;
export const tokenURLs = endpoint.apply(value => urls(value, pkg.service));
