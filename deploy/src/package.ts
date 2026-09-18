// SPDX-License-Identifier: GPL-3.0-or-later
import {execFileSync} from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import {createHash} from "node:crypto";
import {Settings, ServiceConfig} from "./settings";

export interface Package {directory: string; service: ServiceConfig}

// Only local compilation/packaging occurs here. Pulumi providers own cloud lifecycle.
// Every preview validates the config and compiles Go; Docker builds happen on update.
export function prepare(settings: Settings, stack: string): Package {
    const root = path.resolve(__dirname, "../..");
    const builds = path.join(root, "deploy/.build");
    fs.mkdirSync(builds, {recursive: true});
    const temporary = fs.mkdtempSync(path.join(builds, "prepare-"));
    const directory = path.join(builds, createHash("sha256").update(stack + settings.cloud).digest("hex").slice(0, 16));
    const go = (args: string[], env = process.env) => execFileSync("go", args, {cwd: root, env, stdio: ["ignore", "inherit", "inherit"]});
    try {
        go(["run", "./cmd/honeylambda", "bundle", "-config", settings.configFile, "-out", path.join(temporary, "config")]);
        if (settings.cloud === "aws") {
            go(["build", "-trimpath", "-tags", "lambda.norpc", "-ldflags=-s -w", "-o", path.join(temporary, "bootstrap"), "./cmd/honeylambda-lambda"],
                {...process.env, CGO_ENABLED: "0", GOOS: "linux", GOARCH: "arm64"});
        } else {
            // A minimal build context: never copy the working tree or notification credentials.
            for (const file of ["go.mod", "go.sum", "Dockerfile"]) fs.copyFileSync(path.join(root, file), path.join(temporary, file));
            for (const dir of ["cmd/honeylambda", "internal/trap"]) fs.cpSync(path.join(root, dir), path.join(temporary, dir), {recursive: true});
        }
        const service = JSON.parse(fs.readFileSync(path.join(temporary, "config/config.json"), "utf8")) as ServiceConfig;
        fs.rmSync(directory, {recursive: true, force: true});
        fs.renameSync(temporary, directory);
        return {directory, service};
    } catch (error) {
        fs.rmSync(temporary, {recursive: true, force: true});
        throw error;
    }
}
