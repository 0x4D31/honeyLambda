import {test} from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {createHash} from "node:crypto";
import {execFileSync} from "node:child_process";
import {prepare} from "../src/package";

// Exercise the actual Go bundler and compiler, without a cloud account or Docker.
test("packages portable assets and an executable ARM64 Lambda bootstrap", () => {
    const source = fs.mkdtempSync(path.join(os.tmpdir(), "honeylambda-config-"));
    const configFile = path.join(source, "service.json");
    fs.writeFileSync(path.join(source, "body.bin"), Buffer.from([0, 255, 10]));
    fs.writeFileSync(configFile, JSON.stringify({version: 2, default_response: {body_file: "body.bin"}, tokens: [{id: "test", path: "/test"}]}));
    const settings = {cloud: "aws" as const, region: "us-east-1", maxInstances: 2, configFile};
    const created: string[] = [];
    try {
        const lambda = prepare(settings, "test-packaging");
        created.push(lambda.directory);
        const binary = path.join(lambda.directory, "bootstrap");
        assert.notEqual(fs.statSync(binary).mode & 0o111, 0);
        assert.equal(fs.readFileSync(binary).readUInt16LE(18), 183); // ELF EM_AARCH64
        const hash = () => createHash("sha256").update(fs.readFileSync(binary)).digest("hex");
        const initial = hash();
        prepare(settings, "test-packaging");
        assert.equal(hash(), initial, "unchanged Go source produced a different binary");
        const container = prepare({...settings, cloud: "gcp"}, "test-packaging");
        created.push(container.directory);
        assert.ok(fs.existsSync(path.join(container.directory, "Dockerfile")));
        assert.ok(fs.existsSync(path.join(container.directory, "cmd/honeylambda/main.go")));
        assert.equal(fs.existsSync(path.join(container.directory, "deploy")), false);
        // Repackaging replaces the whole snapshot; removed assets cannot linger.
        fs.writeFileSync(path.join(container.directory, "config/stale.body"), "old");
        const again = prepare({...settings, cloud: "gcp"}, "test-packaging");
        assert.equal(again.directory, container.directory);
        assert.equal(fs.existsSync(path.join(again.directory, "config/stale.body")), false);
        fs.rmSync(source, {recursive: true});
        for (const directory of created) execFileSync("go", ["run", "./cmd/honeylambda", "check", "-config", path.join(directory, "config/config.json")], {cwd: "..", stdio: "pipe"});
    } finally {
        fs.rmSync(source, {recursive: true, force: true});
        for (const directory of created) fs.rmSync(directory, {recursive: true, force: true});
    }
});
