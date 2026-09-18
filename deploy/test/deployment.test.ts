import {test} from "node:test";
import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";

for (const cloud of ["aws", "gcp", "azure"]) {
    test(`${cloud} resource contract`, () => {
        const resources: {type: string; name: string; inputs: any}[] = JSON.parse(execFileSync(process.execPath, ["--import", "tsx", "test/program.ts", cloud], {encoding: "utf8"}));
        const one = (type: string, name?: string) => {
            const resource = resources.find(r => r.type === type && (!name || r.name === name));
            assert.ok(resource, `missing ${type} ${name ?? ""}`);
            return resource.inputs;
        };
        if (cloud === "aws") {
            const fn = one("aws:lambda/function:Function");
            assert.equal(fn.runtime, "provided.al2023");
            assert.deepEqual(fn.architectures, ["arm64"]);
            assert.equal(fn.reservedConcurrentExecutions, 3);
            assert.equal(fn.environment.variables.HONEY_CONFIG, "config/config.json");
            assert.ok(fn.code);
            assert.equal(one("aws:lambda/functionUrl:FunctionUrl").authorizationType, "NONE");
            assert.equal(one("aws:lambda/permission:Permission", "public-url").functionUrlAuthType, "NONE");
            assert.equal(one("aws:lambda/permission:Permission", "public-invocation").invokedViaFunctionUrl, true);
            const policy = JSON.parse(one("aws:iam/rolePolicy:RolePolicy").policy);
            assert.deepEqual(policy.Statement[0].Action, ["logs:CreateLogStream", "logs:PutLogEvents"]);
            assert.notEqual(policy.Statement[0].Resource, "*");
            assert.equal(resources.filter(r => r.type.startsWith("docker:")).length, 0);
        } else {
            const image = one("docker:index/image:Image");
            assert.equal(image.build.platform, "linux/amd64");
            assert.equal(image.build.args.CONFIG_DIR, "config");
            assert.equal(image.buildOnPreview, false);
            if (cloud === "gcp") {
                const service = one("gcp:cloudrunv2/service:Service");
                assert.equal(service.deletionProtection, false);
                assert.equal(service.template.scaling.minInstanceCount, 0);
                assert.equal(service.template.scaling.maxInstanceCount, 3);
                assert.equal(service.template.executionEnvironment, "EXECUTION_ENVIRONMENT_GEN2");
                assert.equal(service.template.containers[0].resources.limits.memory, "512Mi");
                assert.match(service.template.containers[0].image, /@sha256:/);
                assert.equal(one("gcp:cloudrunv2/serviceIamMember:ServiceIamMember").member, "allUsers");
                assert.ok(resources.filter(r => r.type === "gcp:projects/service:Service").every(r => r.inputs.disableOnDestroy === false));
                assert.equal(resources.filter(r => r.type === "gcp:projects/iAMMember:IAMMember").length, 0);
                assert.match(one("gcp:serviceaccount/account:Account").accountId, /^[a-z][a-z0-9-]{5,29}$/);
            } else {
                const app = one("azure-native:app:ContainerApp");
                assert.equal(app.configuration.ingress.external, true);
                assert.equal(app.configuration.ingress.allowInsecure, false);
                assert.equal(app.template.scale.minReplicas, 0);
                assert.equal(app.template.scale.maxReplicas, 3);
                assert.match(app.template.containers[0].image, /@sha256:/);
                assert.equal(one("azure-native:containerregistry:Registry").adminUserEnabled, false);
                assert.equal(app.identity.type, "UserAssigned");
                assert.ok(app.configuration.registries[0].identity);
                assert.equal(app.configuration.registries[0].passwordSecretRef, undefined);
                assert.match(one("azure-native:authorization:RoleAssignment").roleDefinitionId, /7f951dda-4ed3-4680-a7ca-43fe172d538d$/);
            }
        }
    });
}
