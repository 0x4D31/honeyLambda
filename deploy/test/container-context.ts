// Used by CI to build the same generated context as cloud deployments.
import * as path from "node:path";
import {prepare} from "../src/package";
const pkg = prepare({cloud: "gcp", region: "us-central1", configFile: path.resolve(__dirname, "../../examples/config.json")}, "container-ci");
process.stdout.write(pkg.directory);
