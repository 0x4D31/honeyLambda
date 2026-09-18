import {test} from "node:test";
import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import * as fs from "node:fs";
import Ajv2020 from "ajv/dist/2020";

const schema = JSON.parse(fs.readFileSync("../config.schema.json", "utf8"));
const validate = new Ajv2020({strict: true, strictRequired: false, allowMatchingProperties: false}).compile(schema);

test("editor schema accepts the example and rejects malformed structures", () => {
    const example = JSON.parse(fs.readFileSync("../examples/config.json", "utf8"));
    assert.ok(validate(example), JSON.stringify(validate.errors));
    const exported = JSON.parse(execFileSync("go", ["run", "./cmd/honeylambda", "export", "-config", "examples/config.json"], {cwd: "..", encoding: "utf8"}));
    assert.ok(validate(exported), JSON.stringify(validate.errors));
    const basic = {version: 2, tokens: [{id: "a", path: "/a"}]};
    assert.ok(validate(basic));
    for (const bad of [
        {...basic, tokens: []}, {...basic, typo: true}, {...basic, alerts: {webhook_url_env: "PORT"}},
        {...basic, tokens: [{id: "a", path: "relative"}]},
        {...basic, tokens: [{id: "a", path: "/a", response: {}, response_ref: "pixel"}]},
        {...basic, default_response: {body: "", body_file: "pixel.png"}},
        {...basic, responses: {pixel: null}}, {...basic, trusted_proxies: null},
    ]) assert.equal(validate(bad), false, JSON.stringify(bad));
});
